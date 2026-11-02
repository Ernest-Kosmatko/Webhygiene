from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import http.client

USER_AGENT = "webhygiene/1.0 (+authorized security assessment)"


@dataclass
class Snapshot:
    url: str
    is_https: bool
    status: int
    headers: dict[str, str]
    set_cookies: list[str]
    redirect_to: str | None = None
    tls_version: str | None = None
    cert_not_after: datetime | None = None
    http_redirects_to_https: bool | None = None
    notes: list[str] = field(default_factory=list)


def _request(scheme: str, host: str, port: int, path: str, timeout: float, verify: bool):
    if scheme == "https":
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    resp = conn.getresponse()
    resp.read(1)
    return conn, resp


def _tls_info(conn) -> tuple[str | None, datetime | None]:
    sock = getattr(conn, "sock", None)
    if not isinstance(sock, ssl.SSLSocket):
        return None, None
    version = sock.version()
    cert = sock.getpeercert()
    not_after = None
    if cert and "notAfter" in cert:
        ts = ssl.cert_time_to_seconds(cert["notAfter"])
        not_after = datetime.fromtimestamp(ts, tz=timezone.utc)
    return version, not_after


def snapshot(url: str, timeout: float = 8.0, verify: bool = True) -> Snapshot:
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    scheme = p.scheme
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")

    conn, resp = _request(scheme, host, port, path, timeout, verify)
    try:
        headers = {k: v for k, v in resp.getheaders()}
        cookies = resp.msg.get_all("Set-Cookie") or []
        tls_version, not_after = _tls_info(conn)
        snap = Snapshot(
            url=url,
            is_https=scheme == "https",
            status=resp.status,
            headers=headers,
            set_cookies=cookies,
            redirect_to=resp.getheader("Location"),
            tls_version=tls_version,
            cert_not_after=not_after,
        )
    finally:
        conn.close()

    if scheme == "https":
        snap.http_redirects_to_https = _http_redirects(host, timeout)
    return snap


def _http_redirects(host: str, timeout: float) -> bool | None:
    """True if plain HTTP on port 80 redirects to HTTPS, None if port 80 is closed."""
    try:
        conn, resp = _request("http", host, 80, "/", timeout, True)
    except (OSError, socket.timeout):
        return None
    try:
        loc = resp.getheader("Location") or ""
        return 300 <= resp.status < 400 and loc.lower().startswith("https://")
    finally:
        conn.close()
