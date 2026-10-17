"""Reviewed input packs and opt-in legacy corpus. No network or file uploads."""

import json
from pathlib import Path

from payloads import PAYLOADS

PACKS = json.loads((Path(__file__).parent / "probe_packs.json").read_text(encoding="utf-8"))


def legacy_corpus():
    """Remove exact name/value/delivery duplicates within each legacy category."""
    clean = {}
    for category, payloads in PAYLOADS.items():
        seen_names, seen_values = set(), set()
        for payload in payloads:
            delivery = {key: value for key, value in payload.items() if key != "name"}
            key = json.dumps(delivery, sort_keys=True)
            if payload["name"] in seen_names or key in seen_values:
                continue
            clean.setdefault(category, []).append(payload)
            seen_names.add(payload["name"])
            seen_values.add(key)
    return clean


def load_pack(name):
    if name == "legacy":
        return legacy_corpus()
    if name == "research":
        return {key: value["probes"] for key, value in PACKS.items() if value.get("research")}
    if name == "core":
        return {key: value["probes"] for key, value in PACKS.items() if key != "demo"}
    return {name: PACKS[name]["probes"]}
