from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "pass": 4}


@dataclass
class Finding:
    check: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def _h(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def check_headers(headers: dict[str, str], is_https: bool) -> list[Finding]:
    """Evaluate security-relevant HTTP response headers."""
    h = _h(headers)
    out: list[Finding] = []

    if is_https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(Finding("HSTS", "medium", "Strict-Transport-Security header missing"))
        else:
            max_age = 0
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        max_age = int(part.split("=", 1)[1])
                    except ValueError:
                        pass
            if max_age < 15552000:
                out.append(Finding("HSTS", "low", f"max-age too short ({max_age}s, recommend >= 15552000)"))
            else:
                out.append(Finding("HSTS", "pass", "enabled with adequate max-age"))

    csp = h.get("content-security-policy")
    if not csp:
        out.append(Finding("CSP", "medium", "Content-Security-Policy header missing"))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        out.append(Finding("CSP", "low", "policy allows 'unsafe-inline' or 'unsafe-eval'"))
    else:
        out.append(Finding("CSP", "pass", "present without unsafe directives"))

    if "x-frame-options" not in h and "frame-ancestors" not in (csp or ""):
        out.append(Finding("Clickjacking", "medium", "no X-Frame-Options or CSP frame-ancestors"))
    else:
        out.append(Finding("Clickjacking", "pass", "framing restricted"))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Finding("X-Content-Type-Options", "low", "nosniff not set"))
    else:
        out.append(Finding("X-Content-Type-Options", "pass", "nosniff set"))

    if "referrer-policy" not in h:
        out.append(Finding("Referrer-Policy", "low", "header missing"))
    else:
        out.append(Finding("Referrer-Policy", "pass", h["referrer-policy"]))

    if "permissions-policy" not in h:
        out.append(Finding("Permissions-Policy", "info", "header missing"))

    for name in ("server", "x-powered-by", "x-aspnet-version"):
        if name in h and any(c.isdigit() for c in h[name]):
            out.append(Finding("Version disclosure", "low", f"{name}: {h[name]}"))

    return out


def check_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    out: list[Finding] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().lower() for a in raw.split(";")[1:]}
        flags = {a.split("=")[0] for a in attrs}
        missing = []
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if is_https and "secure" not in flags:
            missing.append("Secure")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            out.append(Finding("Cookie flags", "medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                               f"{name}: missing {', '.join(missing)}"))
        else:
            out.append(Finding("Cookie flags", "pass", f"{name}: all flags set"))
    return out


def check_tls(version: str | None, not_after: datetime | None, now: datetime | None = None) -> list[Finding]:
    out: list[Finding] = []
    now = now or datetime.now(timezone.utc)

    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        out.append(Finding("TLS version", "high", f"negotiated deprecated protocol {version}"))
    elif version:
        out.append(Finding("TLS version", "pass", f"negotiated {version}"))

    if not_after:
        days = (not_after - now).days
        if days < 0:
            out.append(Finding("Certificate", "high", f"expired {-days} days ago"))
        elif days < 14:
            out.append(Finding("Certificate", "medium", f"expires in {days} days"))
        else:
            out.append(Finding("Certificate", "pass", f"valid for {days} more days"))
    return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check))
