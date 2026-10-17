"""Loopback-only fixture. Returns canned responses; never evaluates inputs."""

import argparse
import json
import threading
import time
import unicodedata
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from tests.parser_fixture import parser_response


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.hits.append((self.command, self.path))
        path = urlsplit(self.path)
        query = parse_qs(path.query)
        size = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(size).decode() if size else ""
        data = {}
        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                data = json.loads(raw or "{}")
                if isinstance(data, dict):
                    query.update({k: [str(v)] for k, v in data.items()})
            except json.JSONDecodeError:
                pass
        else:
            query.update(parse_qs(raw))
        value = query.get("q", query.get("probe", [""]))[0]
        if not value:
            value = self.headers.get(
                "X-Firestorm-Probe", self.headers.get("Cookie", "").removeprefix("session=")
            )
        case = path.path.strip("/") or value
        if case == "mixed":
            case = "deny" if self.command == "GET" else "ok"
        cases = {
            "deny": (403, "Access denied"),
            "broken": (403, "Partial"),
            "ratebroken": (429, "Partial"),
            "signal": (200, "Request blocked by policy"),
            "custom": (418, "Policy response"),
            "error": (503, "Unavailable"),
            "rate": (429, "Slow down"),
            "redirect": (302, "Redirect"),
            "vendor": (200, "Cloudflare AWS Azure SQL injection waf"),
            "echo": (200, value),
            "large": (200, "a" * 100000),
        }
        if case == "slow":
            time.sleep(0.15)
        status, body = cases.get(case, (200, "Fixture response; no input executed"))
        research_case = case in {"json-parser", "xml-parser", "parameters", "research"}
        if research_case:
            self.server.captures.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "body": raw,
                    "content_type": self.headers.get("Content-Type", ""),
                }
            )
            status, body = parser_response(
                case, self.command, path.query, raw, self.headers.get("Content-Type", "")
            )
        elif case == "marker":
            body = value
        elif case == "normalization":
            body = unicodedata.normalize("NFC", unquote(unquote(value)))
        elif case == "boundary":
            status = (
                422
                if isinstance(data, dict)
                and "probe" in data
                and (data["probe"] is None or isinstance(data["probe"], list))
                else 413
                if len(value) > 200
                else 400
                if any(c in value for c in "'\"`<>;&")
                else 200
            )
            body = "Fixture input validation; no input executed"
        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8" if research_case else "text/plain; charset=utf-8",
        )
        if status == 302:
            self.send_header("Location", self.server.redirect_to)
        if status == 429:
            self.send_header("Retry-After", "3600")
        if case in {"broken", "ratebroken"}:
            self.send_header("Content-Length", "1000")
        self.end_headers()
        try:
            self.wfile.write(body.encode())
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_POST = do_GET


@contextmanager
def fixture(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.hits = []
    server.captures = []
    server.redirect_to = "http://127.0.0.1:1/outside"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with fixture(args.port) as (_, url):
        print(f"Fixture listening at {url}", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
