"""Firestorm: bounded HTTP probe observations for authorized lab testing."""

import hashlib
import ipaddress
import time
from urllib.parse import urlsplit

import requests

VERSION = "3.2.0"
RESULTS = (
    "block_signal",
    "no_block_signal",
    "redirect",
    "ambiguous",
    "rate_limited",
    "server_error",
    "transport_error",
    "skipped",
)
FIELDS = (
    "category",
    "name",
    "method",
    "status",
    "result",
    "reason",
    "confirmation",
    "elapsed_ms",
    "body_bytes_sampled",
    "body_truncated",
    "phase",
    "sample_sha256",
    "baseline_status",
    "baseline_result",
    "comparison",
)
BODY_LIMIT = 65536


def detect_blocked(status_code, body, custom_block_status=None):
    """Return observations only. Neither HTTP status nor text proves WAF action."""
    if status_code == 429:
        return "rate_limited", "HTTP 429; source unknown; run stopped"
    if 500 <= status_code <= 599:
        return "server_error", f"HTTP {status_code}; server or intermediary error"
    if 300 <= status_code <= 399:
        return "redirect", f"HTTP {status_code}; redirect not followed"
    if status_code in (custom_block_status or set()):
        return "block_signal", f"configured HTTP {status_code}; WAF attribution unconfirmed"
    # Require a denial phrase, not a vendor name or an echoed attack keyword.
    if "request blocked" in body.lower() or "the requested url was rejected" in body.lower():
        return "block_signal", "denial phrase in response; may be application text or reflection"
    if status_code in {401, 403, 406}:
        return "ambiguous", f"HTTP {status_code}; authentication, application or filtering possible"
    if 200 <= status_code <= 299:
        return "no_block_signal", f"HTTP {status_code}; processing and exploit success unknown"
    return "ambiguous", f"HTTP {status_code}; insufficient attribution evidence"


def validate_target(url, allow_remote=False):
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid target port") from exc
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or parts.query
        or any(c.isspace() for c in url)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("use an HTTP(S) URL without credentials, query or fragment")
    if not allow_remote:
        try:
            local = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            local = False
        if not local:
            raise ValueError("default scope is a literal loopback IP; remote labs require --allow-remote")
    return url


class ProbeClient:
    """One bounded request path: no redirects, proxy env, retries or cookie carryover."""

    def __init__(self, timeout=5, interval=0.2, max_requests=100, cancel=None):
        self.timeout, self.interval, self.max_requests = timeout, interval, max_requests
        self.cancel = cancel
        self.count = 0
        self.last_start = None
        self.stopped = False
        self.session = requests.Session()
        self.session.trust_env = False

    def close(self):
        self.session.close()

    def observe(self, url, category, payload, method, kwargs, custom_block_status=None, phase="probe"):
        row = dict.fromkeys(FIELDS)
        row.update(
            category=category,
            name=payload["name"],
            method=method,
            confirmation="unconfirmed",
            elapsed_ms=0,
            body_bytes_sampled=0,
            body_truncated=False,
            phase=phase,
            comparison="not_collected",
        )
        if self.stopped or self.count >= self.max_requests:
            row.update(result="skipped", reason="rate limit stop or request budget exhausted")
            return row
        if self.last_start is not None:
            delay = max(0, self.interval - (time.monotonic() - self.last_start))
            if self.cancel is not None:
                self.cancel.wait(delay)
            else:
                time.sleep(delay)
        if self.cancel is not None and self.cancel.is_set():
            row.update(result="skipped", reason="cancelled before request")
            return row
        self.session.cookies.clear()
        self.last_start = time.monotonic()
        self.count += 1
        try:
            verb = "POST" if method.startswith("POST") else "GET"
            with self.session.request(
                verb, url, timeout=self.timeout, stream=True, allow_redirects=False, **kwargs
            ) as response:
                row["status"] = response.status_code
                if response.status_code == 429:
                    self.stopped = True
                # Limit decompressed bytes and total body-read duration.
                sample = bytearray()
                for chunk in response.iter_content(chunk_size=4096):
                    sample.extend(chunk[: BODY_LIMIT - len(sample)])
                    if len(sample) >= BODY_LIMIT or time.monotonic() - self.last_start >= self.timeout:
                        row["body_truncated"] = True
                        break
                row["body_bytes_sampled"] = len(sample)
                row["sample_sha256"] = hashlib.sha256(sample).hexdigest()
                body = sample.decode("utf-8", errors="replace")
                row["result"], row["reason"] = detect_blocked(response.status_code, body, custom_block_status)
        except (requests.RequestException, UnicodeError, ValueError) as exc:
            # Keep HTTP evidence when headers arrived but body transfer failed.
            if row["status"] is not None:
                row["result"], row["reason"] = detect_blocked(row["status"], "", custom_block_status)
                row["reason"] += f"; body read failed ({type(exc).__name__})"
                row["body_truncated"] = True
            else:
                row.update(result="transport_error", reason=type(exc).__name__)
        row["elapsed_ms"] = round((time.monotonic() - self.last_start) * 1000)
        return row


def deliveries(category, payload):
    """Yield separate observations; never collapse mixed method outcomes."""
    value = str(payload.get("value", ""))
    for key in ("header_name", "content_type", "method"):
        if key in payload and not isinstance(payload[key], str):
            return
    if payload.get("raw_request") or payload.get("method") not in {None, "path", "cookie", "parameters"}:
        return
    if payload.get("method") == "parameters":
        pairs = payload.get("parameters")
        if not isinstance(pairs, list) or not 1 <= len(pairs) <= 16:
            return
        if not all(
            isinstance(pair, (list, tuple)) and len(pair) == 2 and all(isinstance(item, str) for item in pair)
            for pair in pairs
        ):
            return
        yield "GET+Query", {"params": pairs}
        yield "POST+Form", {"data": pairs}
        return
    if "header_name" in payload:
        header = payload["header_name"]
        # Host/framing overrides would invalidate the scope and transport contract.
        if header.lower() in {"host", "content-length", "transfer-encoding", "connection", "upgrade"}:
            return
        yield "GET+Header", {"headers": {header: value}}
    elif payload.get("content_type") in {"json", "xml"} or category == "xxe":
        content = "xml" if category == "xxe" else payload["content_type"]
        yield (
            "POST+" + content.upper(),
            {"data": value.encode(), "headers": {"Content-Type": "application/" + content}},
        )
    elif payload.get("method") == "cookie":
        yield "GET+Cookie", {"headers": {"Cookie": "session=" + value}}
    else:
        # Path probes use the exact configured endpoint with file=; never change scope.
        param = "file" if category == "path_traversal_lfi" or payload.get("method") == "path" else "q"
        yield "GET+Query", {"params": {param: value}}
        yield "POST+Form", {"data": {param: value}}
        yield "POST+JSON", {"json": {param: value}}


def send_payload(client, url, category, payload, custom_block_status=None):
    attempts = list(deliveries(category, payload))
    if not attempts:
        return [
            {
                **dict.fromkeys(FIELDS),
                "category": category,
                "name": payload["name"],
                "method": "UNSUPPORTED",
                "result": "skipped",
                "confirmation": "unconfirmed",
                "phase": "probe",
                "comparison": "not_collected",
                "reason": "raw, framing or unsupported delivery; no request sent",
            }
        ]
    rows = []
    for method, kwargs in attempts:
        rows.append(client.observe(url, category, payload, method, kwargs, custom_block_status))
        if client.stopped or client.count >= client.max_requests:
            break
    return rows
