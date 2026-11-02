import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from webhygiene.cli import run


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Demo/1.2")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def test_plain_http_target_reports_findings():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url, findings = run(f"http://127.0.0.1:{srv.server_port}/", 3.0, True)
    finally:
        srv.shutdown()
    names = {(f.check, f.severity) for f in findings}
    assert ("Transport", "high") in names
    assert ("CSP", "medium") in names
    assert any(f.check == "Cookie flags" for f in findings)
    assert findings[0].severity == "high"
