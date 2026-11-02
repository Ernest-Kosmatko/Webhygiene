from __future__ import annotations

import argparse
import json
import sys

from .checks import (Finding, check_cookies, check_headers, check_tls,
                     sort_findings)
from .fetch import snapshot
from .report import to_html, to_text


def run(url: str, timeout: float, verify: bool) -> tuple[str, list[Finding]]:
    snap = snapshot(url, timeout=timeout, verify=verify)
    findings: list[Finding] = []
    findings += check_headers(snap.headers, snap.is_https)
    findings += check_cookies(snap.set_cookies, snap.is_https)
    if snap.is_https:
        findings += check_tls(snap.tls_version, snap.cert_not_after)
        if snap.http_redirects_to_https is False:
            findings.append(Finding("HTTP redirect", "medium", "port 80 does not redirect to HTTPS"))
        elif snap.http_redirects_to_https:
            findings.append(Finding("HTTP redirect", "pass", "port 80 redirects to HTTPS"))
    else:
        findings.append(Finding("Transport", "high", "target served over plain HTTP"))
    return snap.url, sort_findings(findings)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="webhygiene",
        description="Check HTTP security headers, cookies and TLS basics. Authorized targets only.",
    )
    p.add_argument("url")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    p.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    p.add_argument("-o", "--out", help="write report to this file instead of stdout")
    args = p.parse_args(argv)

    try:
        url, findings = run(args.url, args.timeout, not args.insecure)
    except Exception as exc:  # network, TLS and DNS errors all end the run the same way
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        body = json.dumps({"target": url, "findings": [f.to_dict() for f in findings]}, indent=2)
    elif args.format == "html":
        body = to_html(url, findings)
    else:
        body = to_text(url, findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"report written to {args.out}")
    else:
        print(body)

    return 2 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
