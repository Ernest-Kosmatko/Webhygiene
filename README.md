# webhygiene

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://github.com/Ernest-Kosmatko/webhygiene/actions/workflows/tests.yml/badge.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)

Checks a web endpoint for common security configuration problems: missing or weak HTTP security headers, insecure cookie flags, deprecated TLS versions, near-expiry certificates and missing HTTP to HTTPS redirects. Standard library only.

> Run it only against targets you are authorized to assess.

## Checks

| Area | What is checked |
|---|---|
| Headers | HSTS (presence and max-age), CSP (presence, `unsafe-inline`/`unsafe-eval`), clickjacking protection, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| Disclosure | Version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version` |
| Cookies | `HttpOnly`, `Secure`, `SameSite` |
| TLS | Negotiated protocol version, certificate expiry |
| Transport | Plain HTTP target, port 80 redirect to HTTPS |

Findings are sorted by severity (`high`, `medium`, `low`, `info`, `pass`). The exit code is `2` when any high finding exists, which makes it usable in CI.

## Install

```bash
git clone https://github.com/Ernest-Kosmatko/webhygiene.git
cd webhygiene
pip install -e .
```

## Usage

```bash
webhygiene https://example.com
webhygiene https://example.com -f html -o report.html
webhygiene https://staging.internal --insecure -f json
```

## Design

- `checks.py` holds pure functions that take data and return findings, so the logic is unit tested without network access.
- `fetch.py` does the network work and returns a `Snapshot`.
- `report.py` renders text and HTML.

## Tests

```bash
pip install -e .[dev]
pytest
```

## Limitations

- Checks one URL and does not crawl
- With `--insecure` the certificate is not retrieved, so the expiry check is skipped
- Does not enumerate supported cipher suites; it reports only the negotiated version

## License

MIT
