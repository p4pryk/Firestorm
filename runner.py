"""Shared, cancellable scan loop. Baselines consume the same request budget."""

import csv
import io
import json
import time
from dataclasses import dataclass, field
from threading import Event

from engine import FIELDS, ProbeClient, deliveries, send_payload

CONTROL = "firestorm-control"


@dataclass
class ScanConfig:
    url: str
    timeout: float = 5
    interval: float = 0.2
    max_requests: int = 100
    block_status: set = field(default_factory=set)
    baseline: bool = True


def neutral_fields(fields):
    if isinstance(fields, dict):
        return {key: CONTROL for key in fields}
    # Ordered pairs keep repeated names; converting them to a dict loses the probe.
    return [[key, CONTROL] for key, _ in fields]


def neutral_delivery(kwargs):
    """Keep transport/field names, replace the input; no attack-trigger baseline."""
    control = {}
    for key in ("params", "json"):
        if key in kwargs:
            control[key] = neutral_fields(kwargs[key])
    if "headers" in kwargs:
        control["headers"] = {
            key: value if key.lower() == "content-type" else CONTROL
            for key, value in kwargs["headers"].items()
        }
        if "Cookie" in control["headers"]:
            control["headers"]["Cookie"] = "session=" + CONTROL
    if "data" in kwargs:
        if isinstance(kwargs["data"], (dict, list)):
            control["data"] = neutral_fields(kwargs["data"])
        else:
            content = kwargs.get("headers", {}).get("Content-Type")
            control["data"] = (
                '{"probe":"firestorm-control"}'
                if content == "application/json"
                else "<probe>firestorm-control</probe>"
            )
    return control


def baseline_key(method, control):
    return method, json.dumps(control, sort_keys=True)


def compare(row, baseline):
    if baseline is None:
        return "not_collected"
    if baseline["status"] is None:
        return "unavailable"
    if baseline["result"] != "no_block_signal":
        return "baseline_inconclusive"
    if row["status"] is None or row["body_truncated"] or baseline["body_truncated"]:
        return "incomplete_sample"
    if row["status"] == baseline["status"] and row["sample_sha256"] == baseline["sample_sha256"]:
        return "same_sample"
    return "different_sample"


def planned_requests(corpus, baseline=True):
    count, controls = 0, set()
    for category, payloads in corpus.items():
        for payload in payloads:
            for method, kwargs in deliveries(category, payload):
                count += 1
                controls.add(baseline_key(method, neutral_delivery(kwargs)))
    return count + (len(controls) if baseline else 0)


def run_scan(config, corpus, on_row=None, cancel=None):
    cancel = cancel if cancel is not None else Event()
    client = ProbeClient(config.timeout, config.interval, config.max_requests, cancel=cancel)
    rows, controls = [], {}
    started = time.monotonic()

    def record(row):
        row["id"] = len(rows) + 1
        rows.append(row)
        if on_row:
            on_row(row.copy(), client.count)

    def done():
        return cancel.is_set() or client.stopped or client.count >= client.max_requests

    try:
        for category, payloads in corpus.items():
            for payload in payloads:
                if done():
                    break
                attempts = list(deliveries(category, payload))
                if not attempts:
                    record(send_payload(client, config.url, category, payload)[0])
                for method, kwargs in attempts:
                    if done():
                        break
                    baseline = None
                    if config.baseline:
                        control = neutral_delivery(kwargs)
                        key = baseline_key(method, control)
                        if key not in controls:
                            baseline = client.observe(
                                config.url,
                                "baseline",
                                {"name": "neutral_control"},
                                method,
                                control,
                                config.block_status,
                                phase="baseline",
                            )
                            baseline["comparison"] = "control"
                            controls[key] = baseline
                            record(baseline)
                        baseline = controls[key]
                    if done():
                        break
                    row = client.observe(config.url, category, payload, method, kwargs, config.block_status)
                    row["comparison"] = compare(row, baseline)
                    if baseline:
                        row.update(baseline_status=baseline["status"], baseline_result=baseline["result"])
                    record(row)
            if done():
                break
    except KeyboardInterrupt:
        cancel.set()
    finally:
        client.close()
    reason = (
        "cancelled"
        if cancel.is_set()
        else "rate_limited"
        if client.stopped
        else "budget_reached"
        if client.count >= config.max_requests
        else "completed"
    )
    return {
        "rows": rows,
        "requests": client.count,
        "stop_reason": reason,
        "planned": planned_requests(corpus, config.baseline),
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }


def csv_text(rows):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=("id", *FIELDS), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                key: (
                    "'" + value
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                    else value
                )
                for key, value in row.items()
            }
        )
    return buffer.getvalue()
