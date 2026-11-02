from datetime import datetime, timedelta, timezone

from webhygiene.checks import check_cookies, check_headers, check_tls


def by_check(findings, name):
    return [f for f in findings if f.check == name]


def test_missing_headers_flagged():
    f = check_headers({}, is_https=True)
    assert by_check(f, "HSTS")[0].severity == "medium"
    assert by_check(f, "CSP")[0].severity == "medium"
    assert by_check(f, "Clickjacking")[0].severity == "medium"


def test_good_headers_pass():
    f = check_headers({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }, is_https=True)
    assert all(x.severity in ("pass", "info") for x in f)


def test_weak_hsts_and_csp():
    f = check_headers({
        "Strict-Transport-Security": "max-age=60",
        "Content-Security-Policy": "script-src 'unsafe-inline'",
    }, is_https=True)
    assert by_check(f, "HSTS")[0].severity == "low"
    assert by_check(f, "CSP")[0].severity == "low"


def test_version_disclosure():
    f = check_headers({"Server": "Apache/2.4.49"}, is_https=False)
    assert by_check(f, "Version disclosure")


def test_cookie_flags():
    f = check_cookies(["sid=abc; Path=/", "ok=1; Secure; HttpOnly; SameSite=Lax"], is_https=True)
    assert f[0].severity == "medium" and "HttpOnly" in f[0].detail
    assert f[1].severity == "pass"


def test_tls_expired_and_old():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f = check_tls("TLSv1", now - timedelta(days=3), now)
    assert by_check(f, "TLS version")[0].severity == "high"
    assert by_check(f, "Certificate")[0].severity == "high"


def test_tls_ok():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    f = check_tls("TLSv1.3", now + timedelta(days=90), now)
    assert all(x.severity == "pass" for x in f)
