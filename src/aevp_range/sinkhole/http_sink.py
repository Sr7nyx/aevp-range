"""Stdlib HTTP sinkhole. Accepts any method/path, records body + query + headers
to the event log as a 'sinkhole' event tagged with the current run_id (from env).

Run as a service:  python -m aevp_range.sinkhole.http_sink
It binds AEVP_SINK_HOST:AEVP_SINK_PORT (default 127.0.0.1:8080).
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import eventlog


class _Handler(BaseHTTPRequestHandler):
    def _record(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        run_id = self.headers.get("X-AEVP-Run", os.environ.get("AEVP_RUN_ID", "unknown"))
        eventlog.emit(
            "sinkhole", "http_sink", run_id,
            method=method, path=self.path, body=body,
            headers={k: v for k, v in self.headers.items()},
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_GET(self):   # noqa: N802
        self._record("GET")

    def do_POST(self):  # noqa: N802
        self._record("POST")

    def log_message(self, *args):  # silence default stderr logging
        return


def serve(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    host = host or os.environ.get("AEVP_SINK_HOST", "127.0.0.1")
    port = int(port or os.environ.get("AEVP_SINK_PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), _Handler)
    return httpd


if __name__ == "__main__":
    srv = serve()
    print(f"[sinkhole] listening on http://{srv.server_address[0]}:{srv.server_address[1]}")
    srv.serve_forever()
