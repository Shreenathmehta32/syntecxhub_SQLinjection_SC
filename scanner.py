#!/usr/bin/env python3
"""
Simple SQL Injection Scanner (Educational Use Only)

Only test targets you own or have explicit authorization to assess.
"""

from __future__ import annotations

import argparse
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests
from requests import Response
from requests.exceptions import RequestException

DEFAULT_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
]

SQL_ERROR_PATTERNS = [
    "sql",
    "syntax",
    "mysql",
    "sqlite",
    "postgres",
    "odbc",
    "database error",
    "sqlstate",
    "warning: mysql",
    "unclosed quotation mark",
    "you have an error in your sql syntax",
]


@dataclass
class ScanResult:
    payload: str
    vulnerable: bool
    reason: str
    status_code: int | None = None
    response_length: int | None = None


def validate_target_url(url: str) -> Tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "URL must start with http:// or https://"
    if not parsed.netloc:
        return False, "URL is missing hostname"
    if "=" not in parsed.query:
        return False, "URL must include at least one query parameter, e.g. ?id=1"
    return True, ""


def load_payloads(payload_file: str) -> List[str]:
    if not os.path.exists(payload_file):
        return DEFAULT_PAYLOADS.copy()

    payloads: List[str] = []
    with open(payload_file, "r", encoding="utf-8") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            payloads.append(line)

    return payloads if payloads else DEFAULT_PAYLOADS.copy()


def inject_payload_into_all_params(target_url: str, payload: str) -> str:
    parsed = urlparse(target_url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)

    # Replace each query parameter value with the same payload for a simple broad test.
    injected_items = [(key, payload) for key, _ in query_items]
    new_query = urlencode(injected_items, doseq=True)

    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


def analyze_response(
    response: Response,
    baseline_length: int | None,
    length_threshold_ratio: float,
) -> Tuple[bool, str]:
    body_lower = response.text.lower()

    for marker in SQL_ERROR_PATTERNS:
        if marker in body_lower:
            return True, f"Detected SQL-related marker: '{marker}'"

    if baseline_length is not None and baseline_length > 0:
        current_len = len(response.text)
        difference_ratio = abs(current_len - baseline_length) / baseline_length
        if difference_ratio >= length_threshold_ratio:
            return (
                True,
                f"Large response size difference detected ({difference_ratio:.2%})",
            )

    return False, "No obvious SQL error pattern detected"


def test_payload(
    session: requests.Session,
    target_url: str,
    payload: str,
    timeout: int,
    delay_seconds: float,
    baseline_length: int | None,
    length_threshold_ratio: float,
) -> ScanResult:
    injected_url = inject_payload_into_all_params(target_url, payload)

    if delay_seconds > 0:
        time.sleep(delay_seconds)

    try:
        response = session.get(injected_url, timeout=timeout)
        vulnerable, reason = analyze_response(
            response=response,
            baseline_length=baseline_length,
            length_threshold_ratio=length_threshold_ratio,
        )
        return ScanResult(
            payload=payload,
            vulnerable=vulnerable,
            reason=reason,
            status_code=response.status_code,
            response_length=len(response.text),
        )
    except RequestException as exc:
        return ScanResult(
            payload=payload,
            vulnerable=False,
            reason=f"Request failed: {exc}",
            status_code=None,
            response_length=None,
        )


def write_results_header(results_path: str, target_url: str) -> None:
    with open(results_path, "w", encoding="utf-8") as file:
        file.write("SQL Injection Scanner Results\n")
        file.write("=" * 40 + "\n")
        file.write(f"Target: {target_url}\n")
        file.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        file.write("=" * 40 + "\n")


def append_result_line(results_path: str, line: str, lock: threading.Lock) -> None:
    with lock:
        with open(results_path, "a", encoding="utf-8") as file:
            file.write(line + "\n")


def fetch_baseline_length(session: requests.Session, target_url: str, timeout: int) -> int | None:
    try:
        response = session.get(target_url, timeout=timeout)
        return len(response.text)
    except RequestException:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simple SQL Injection scanner for authorized testing only."
    )
    parser.add_argument("-u", "--url", help="Target URL (must include query parameters)")
    parser.add_argument(
        "-p",
        "--payload-file",
        default="payloads.txt",
        help="Path to payload list file (default: payloads.txt)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="results.txt",
        help="Path to results file (default: results.txt)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        help="Number of worker threads (recommended: 5-10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay before each request in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Request timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--length-threshold",
        type=float,
        default=0.3,
        help="Response length difference ratio threshold (default: 0.3)",
    )
    parser.add_argument(
        "--ack-authorized",
        action="store_true",
        help="Confirm you are authorized to test this target",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.ack_authorized:
        print("[!] Refusing to scan without --ack-authorized")
        print("[!] Only test targets you own or have explicit permission to assess.")
        return

    target_url = args.url or input("Enter target URL (example: http://127.0.0.1/item.php?id=1): ").strip()

    valid, message = validate_target_url(target_url)
    if not valid:
        print(f"[!] Invalid target URL: {message}")
        return

    threads = max(1, min(args.threads, 10))
    payloads = load_payloads(args.payload_file)

    if not payloads:
        print("[!] No payloads available. Add payloads to payloads.txt")
        return

    print(f"[+] Scanning target: {target_url}")
    print(f"[+] Loaded payloads: {len(payloads)}")
    print(f"[+] Using threads: {threads}")
    print(f"[+] Delay per request: {args.delay}s")

    write_results_header(args.output, target_url)
    log_lock = threading.Lock()

    with requests.Session() as session:
        baseline_length = fetch_baseline_length(session, target_url, args.timeout)
        if baseline_length is not None:
            print(f"[+] Baseline response length: {baseline_length}")
        else:
            print("[!] Could not fetch baseline response; continuing without baseline comparison")

        futures = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for payload in payloads:
                print(f"[*] Testing payload: {payload}")
                future = executor.submit(
                    test_payload,
                    session,
                    target_url,
                    payload,
                    args.timeout,
                    args.delay,
                    baseline_length,
                    args.length_threshold,
                )
                futures.append(future)

            vulnerable_count = 0
            for future in as_completed(futures):
                result = future.result()
                status = "Vulnerable" if result.vulnerable else "Not Vulnerable"
                line = f"Payload: {result.payload} -> {status} | {result.reason}"

                if result.vulnerable:
                    vulnerable_count += 1
                    print(f"[!] Possible SQL Injection detected: {line}")
                else:
                    print(f"[-] {line}")

                append_result_line(args.output, line, log_lock)

    print("[+] Scan completed")
    print(f"[+] Potentially vulnerable payloads: {vulnerable_count}/{len(payloads)}")
    print(f"[+] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
