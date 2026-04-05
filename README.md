# SQL Injection Scanner (Educational)

A simple Python-based SQL Injection scanner for beginner-to-intermediate learning.

## Disclaimer

Use this tool **only** on systems you own or are explicitly authorized to test.
Do not scan real/production websites without written permission.

Suggested safe targets:
- DVWA (local)
- OWASP Juice Shop (local)
- Deliberately vulnerable lab apps
- Approved vulnweb-style practice targets

## Features

- Accepts target URL input with query parameters (e.g. `?id=1`)
- Loads payloads from `payloads.txt`
- Replaces URL query parameter values with payloads
- Sends GET requests using `requests`
- Detects likely SQL issues via:
  - SQL-related error keywords
  - Optional large response length differences
- Runs payload checks in parallel with `ThreadPoolExecutor`
- Supports basic rate limiting via request delay
- Logs output to `results.txt` and prints to console

## Files

- `scanner.py` - Main scanner script
- `payloads.txt` - Payload list
- `results.txt` - Output log file
- `README.md` - Documentation

## Requirements

- Python 3.9+
- `requests`

Install dependency:

```bash
pip install requests
```

## Usage

Interactive URL input:

```bash
python scanner.py --ack-authorized
```

Direct URL input:

```bash
python scanner.py -u "http://127.0.0.1/vuln.php?id=1" --ack-authorized
```

With options:

```bash
python scanner.py \
  -u "http://127.0.0.1/vuln.php?id=1" \
  -p payloads.txt \
  -o results.txt \
  -t 5 \
  --delay 0.5 \
  --timeout 8 \
  --length-threshold 0.3 \
  --ack-authorized
```

## Notes

- This is intentionally simple and not comparable to advanced tools (e.g., sqlmap).
- Detection is heuristic and may produce false positives/false negatives.
- For learning, inspect responses manually for confirmation.
