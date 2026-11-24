"""Deliberately weak local target for lab demos (stdlib only).

Starts two listeners on 127.0.0.1:
  <web>     HTTP  - missing security headers, verbose Server banner,
                    unauthenticated /admin, browsable /files/ index
  <telnet>  TCP   - plaintext telnet-style greeting

Only for scanning your own machine. Run:  python labs/weak_target.py
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_PORT = 8099
TELNET_PORT = 9001

INDEX_PAGE = """<html><body><h1>Index of /files/</h1>
<pre><a href="backup.zip">backup.zip</a>
<a href="notes.txt">notes.txt</a></pre></body></html>"""

ADMIN_PAGE = """<html><body><h1>Admin console</h1>
<p>No authentication configured on this listener.</p></body></html>"""


class WeakHandler(BaseHTTPRequestHandler):
    server_version = "DemoWeb/1.4.2"
    sys_version = "Python/3.10.6"

    def _reply(self, body: bytes) -> None:
        self.send_response(200)
        # Deliberately no CSP / X-Frame-Options / X-Content-Type-Options / HSTS
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self._reply(b"")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/admin"):
            self._reply(ADMIN_PAGE.encode())
        elif path.startswith("/files"):
            self._reply(INDEX_PAGE.encode())
        else:
            self._reply(b"<html><body><h1>Demo service</h1></body></html>")

    def log_message(self, *args):
        pass


def start_web(port: int = WEB_PORT) -> ThreadingHTTPServer:
    """port=0 picks a free ephemeral port (used by the test suite)."""
    httpd = ThreadingHTTPServer(("127.0.0.1", port), WeakHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def start_telnet_stub(port: int = TELNET_PORT) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.sendall(b"\r\nWelcome to Demo Telnet Service\r\nlogin: ")
            except OSError:
                pass
            finally:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def start_all(web_port: int = WEB_PORT, telnet_port: int = TELNET_PORT):
    httpd = start_web(web_port)
    telnet = start_telnet_stub(telnet_port)
    print(f"weak HTTP   target -> http://127.0.0.1:{httpd.server_address[1]}")
    print(f"weak telnet target -> 127.0.0.1:{telnet.getsockname()[1]}")
    return httpd, telnet


if __name__ == "__main__":
    start_all()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopped")
