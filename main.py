"""Firestorm console interface for bounded HTTP response observations."""

import argparse
import json
import math
import sys

from rich.console import Console

# Preserve the small public helpers used by scripts and regression tests.
from engine import BODY_LIMIT as BODY_LIMIT
from engine import FIELDS as FIELDS
from engine import RESULTS as RESULTS
from engine import ProbeClient as ProbeClient
from engine import detect_blocked as detect_blocked
from engine import send_payload as send_payload
from engine import validate_target
from packs import PACKS, load_pack
from payload_io import _audit_payloads, _load_extra_payloads_file, _merge_extra_payloads
from payloads import PAYLOADS
from runner import ScanConfig
from terminal_ui import report, run_terminal


def print_report(results, csv_path=None):
    report(Console(), results, csv_path)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Firestorm: HTTP observations, not exploit validation")
    parser.add_argument("--url", help="Exact HTTP(S) lab endpoint (literal loopback by default)")
    parser.add_argument("--host", help="Legacy literal IP/hostname; prefer --url")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument(
        "--allow-remote", action="store_true", help="Explicitly permit an authorized remote lab"
    )
    parser.add_argument("--block-status", help="Comma-separated status signals; never confirms WAF action")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--interval", type=float, default=0.2, help="Minimum seconds between request starts")
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--category", action="append", help="Select a category; repeatable")
    parser.add_argument("--payloads-only", help="Use only this JSON/CSV/TXT input file")
    parser.add_argument("--extra-payloads", action="append", default=[])
    parser.add_argument("--audit-payloads", action="store_true")
    parser.add_argument("--pack", default="core", choices=(*PACKS, "core", "research", "legacy"))
    parser.add_argument("--no-baseline", action="store_true", help="Disable neutral controls")
    parser.add_argument("--save-terminal", help="Save the actual terminal rendering as SVG")
    parser.add_argument("--plain", action="store_true", help="Disable terminal colors")
    parser.add_argument("--csv", default="firestorm-results.csv")
    parser.add_argument("--no-csv", action="store_true")
    args = parser.parse_args(argv)
    if args.audit_payloads:
        return args
    if args.url and args.host:
        parser.error("choose --url or --host")
    if not args.url and not args.host:
        parser.error("--url is required")
    if args.host:
        host = args.host
        if any(c in host for c in "/?#@"):
            parser.error("--host must be a bare host")
        if ":" in host and not host.startswith("["):
            host = "[" + host + "]"
        args.url = f"http://{host}:{args.port}/"
    try:
        validate_target(args.url, args.allow_remote)
        if (
            not math.isfinite(args.timeout)
            or not math.isfinite(args.interval)
            or args.timeout <= 0
            or args.interval < 0
            or args.max_requests <= 0
        ):
            raise ValueError(
                "timeout/budget must be positive and interval nonnegative; values must be finite"
            )
        args.block_status = (
            {int(code) for code in args.block_status.split(",")} if args.block_status else set()
        )
        if any(code < 100 or code > 599 for code in args.block_status):
            raise ValueError("block statuses must be between 100 and 599")
    except ValueError as exc:
        parser.error(str(exc))
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.audit_payloads:
        print(json.dumps(_audit_payloads(PAYLOADS), indent=2))
        return 0
    try:
        corpus = _load_extra_payloads_file(args.payloads_only) if args.payloads_only else load_pack(args.pack)
        for path in args.extra_payloads:
            corpus, _ = _merge_extra_payloads(corpus, _load_extra_payloads_file(path))
        if args.category:
            if set(args.category) - corpus.keys():
                raise ValueError("unknown category")
            corpus = {cat: values for cat, values in corpus.items() if cat in args.category}
        if not any(corpus.values()):
            raise ValueError("no valid payloads selected")
        config = ScanConfig(
            args.url,
            args.timeout,
            args.interval,
            args.max_requests,
            args.block_status,
            baseline=not args.no_baseline,
        )
        outcome = run_terminal(
            config, corpus, None if args.no_csv else args.csv, args.plain, args.save_terminal
        )
    except KeyboardInterrupt:
        print("\nInterrupted while preparing terminal output.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"Input/output error: {exc}", file=sys.stderr)
        return 2
    if outcome["stop_reason"] == "cancelled":
        return 130
    return (
        1
        if outcome["stop_reason"] == "rate_limited"
        or any(row["result"] in {"transport_error", "server_error"} for row in outcome["rows"])
        else 0
    )


if __name__ == "__main__":
    sys.exit(main())
