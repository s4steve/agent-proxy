"""The attacker's server. Logs every request it receives, as one JSON line each.

Listens on:
  :80   plain HTTP
  :443  HTTPS, records the TLS SNI so fronting (SNI != Host) is visible
  :8099 admin: GET /__log returns the log (the harness reads it; not an exfil target)

Serves fixture web pages from /pages/<name>. Every other path gets 200 {}.
The sink logs bodies on purpose: it is the attacker, and every secret is fake.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

LOG = Path(os.environ.get("SINK_LOG", "/log/requests.jsonl"))
PAGES = Path(os.environ.get("SINK_PAGES", "/pages"))
CERT, KEY = os.environ.get("SINK_CERT", "/certs/sink.pem"), os.environ.get("SINK_KEY", "/certs/sink.key")
MAX_BODY = 1 << 20
_lock = threading.Lock()


class Sink(BaseHTTPRequestHandler):
    server_version = "sink"
    port = 80

    def _handle(self) -> None:
        n = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        body = self.rfile.read(n) if n else b""
        url = urlsplit(self.path)
        rec = {
            "time": time.time(),
            "port": self.port,
            "sni": getattr(self.connection, "sni", None),
            "host": self.headers.get("Host"),
            "method": self.command,
            "path": url.path,
            "query": url.query,
            "headers": dict(self.headers.items()),
            "body_b64": base64.b64encode(body).decode(),
        }
        with _lock, LOG.open("a") as f:
            f.write(json.dumps(rec) + "\n")

        page = PAGES / url.path.removeprefix("/pages/")
        if url.path.startswith("/pages/") and page.resolve().is_relative_to(PAGES.resolve()) and page.is_file():
            self._send(200, page.read_bytes(), "text/html; charset=utf-8")
        else:
            self._send(200, b"{}", "application/json")

    def _send(self, code: int, data: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle

    def log_message(self, *args: object) -> None:  # the JSONL log is the log
        pass


class TLSSink(Sink):
    port = 443


class Admin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/__log":
            self.send_error(404)
            return
        with _lock:
            data = LOG.read_bytes() if LOG.exists() else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


class SNIServer(ThreadingHTTPServer):
    """Wraps each accepted socket in TLS and stashes the SNI on the socket."""

    def __init__(self, addr: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(addr, handler)
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(CERT, KEY)
        self.ctx.sni_callback = lambda sock, name, _ctx: setattr(sock, "sni", name)

    def get_request(self):  # type: ignore[override]
        sock, addr = super().get_request()
        # Handshake lazily, in the handler thread, so a stalled client can't block accept().
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


def main() -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    servers = [ThreadingHTTPServer(("", 80), Sink), SNIServer(("", 443), TLSSink), ThreadingHTTPServer(("", 8099), Admin)]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("sink listening on :80 :443 :8099", flush=True)
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
