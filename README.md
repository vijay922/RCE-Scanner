# Remote Command Execution RCE

## Overview

This Go script is an automated security testing tool that scans URLs for potential **Remote Command Execution (RCE) vulnerabilities**. It injects various payloads into different parts of the URL and HTTP headers, analyzes the responses, and detects signs of successful command execution.

## Features

- **Multiple Injection Points**: Tests payloads in URL paths, query parameters, and HTTP headers.
- **Diverse Payloads**: Uses various encoding techniques to bypass filters.
- **Multi-threaded Execution**: Supports concurrent requests for faster scanning.
- **Custom User-Agents**: Mimics real-world user behavior.
- **Logging**: Saves results to an output file if specified.
- **Verbose Mode**: Provides detailed execution logs.

## How It Works

1. Reads URLs from **stdin** (standard input).
2. Parses each URL and injects payloads in different locations:
   - URL Path Segments
   - Query Parameters
   - HTTP Headers (e.g., `User-Agent`, `X-Forwarded-For`, `Referer`)
3. Sends HTTP requests with the modified URLs/headers.
4. Examines server responses for signs of command execution (`uid=`, etc.).
5. Reports potential vulnerabilities.

## Installation

Ensure you have Go installed and set up on your system.

```sh
# Clone the repository
git clone https://github.com/vijay922/RCE-Scanner.git
cd RCE-Scanner

# Build the binary
go build -o rce-scanner
```

## Usage

```sh
cat urls.txt | ./rce-scanner -t 20 -v -o results.txt
```

### Options:

- `-t <threads>`: Set concurrency level (default: `10`).
- `-v`: Enable verbose mode.
- `-o <file>`: Save results to a file.

## Example Payloads

The scanner includes payloads such as:

```json
[
  {"Payload": ";/usr/bin/id\n", "Encoding": "none", "MatchRegex": "uid=\\d+\\(.+?\\)"},
  {"Payload": "%0Aid%0A", "Encoding": "url", "MatchRegex": "uid="},
  {"Payload": "${{SHELL}:-/bin/sh} -c 'id'", "Encoding": "env-var", "MatchRegex": "uid="}
]
```

## Output Format

If a potential vulnerability is detected, output looks like:

```
[+] Potential RCE Vulnerability at http://example.com/test
    Payload: ;/usr/bin/id
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
    Match: uid=1000(user)
```

## Disclaimer

**Use this tool only for ethical hacking and authorized penetration testing.** Unauthorized use is illegal.

## License

This project is licensed under the MIT License.

---
