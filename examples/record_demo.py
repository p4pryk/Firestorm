"""Record three real terminal runs against a loopback-only fixture."""

import csv
import os
import subprocess
import sys
from pathlib import Path

from tests.fixture import fixture


def capture(url, pack, name, svg, expected_code, expected_rows):
    csv_path = Path(f"examples/{name}-results.csv")
    csv_path.unlink(missing_ok=True)
    args = [
        sys.executable,
        "main.py",
        "--url",
        url,
        "--pack",
        pack,
        "--block-status",
        "418",
        "--interval",
        "0.05",
        "--csv",
        str(csv_path),
        "--save-terminal",
        f"docs/images/{svg}.svg",
    ]
    run = subprocess.run(
        args, capture_output=True, text=True, check=False, timeout=30, env={**os.environ, "COLUMNS": "132"}
    )
    transcript = (
        "$ python main.py "
        + " ".join(args[2:])
        + "\n"
        + run.stdout
        + f"\nProcess exit code: {run.returncode} (expected {expected_code})\n"
    )
    path = "examples/demo.txt" if name == "demo" else f"examples/{name}-demo.txt"
    Path(path).write_text(transcript, encoding="utf-8")
    print(transcript, end="")
    if run.stderr:
        print(run.stderr, file=sys.stderr)
    if run.stderr or run.returncode != expected_code:
        return False
    with csv_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return len(rows) == expected_rows and (pack != "demo" or rows[-1]["result"] == "rate_limited")


def main():
    with fixture() as (_, url):
        demo = capture(url, "demo", "demo", "terminal", 1, 25)
        boundary = capture(url + "boundary", "boundaries", "boundaries", "boundaries", 0, 12)
        research = capture(url + "research", "research", "research", "research", 0, 26)
    return 0 if demo and boundary and research else 1


if __name__ == "__main__":
    sys.exit(main())
