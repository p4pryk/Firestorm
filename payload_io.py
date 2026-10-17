"""Load, merge and audit probe inputs without network access."""

import csv
import difflib
import json
import os
import re
from typing import Dict, List, Tuple

from payloads import Payload


def _normalize_payload_value(value: str) -> str:
    normalized = value.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def _similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _load_extra_payloads_file(path: str) -> Dict[str, List[Payload]]:
    """Load extra payloads from a user-supplied file.

    Supported formats:
      - .json: {"category": [{"name": "...", "value": "..."}, ...], ...}
               OR [{"category": "...", "name": "...", "value": "..."}, ...]
      - .csv: columns: category,name,value
      - .txt/.tsv: lines: category<TAB>name<TAB>value or category|name|value
    """

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        out: Dict[str, List[Payload]] = {}
        if isinstance(data, dict):
            for category, payloads in data.items():
                if not isinstance(payloads, list):
                    continue
                out.setdefault(str(category), [])
                for item in payloads:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", "")).strip()
                    value = str(item.get("value", ""))
                    if not name or not value:
                        continue
                    out[str(category)].append({**item, "name": name, "value": value})
            return out

        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                category = str(item.get("category", "")).strip()
                name = str(item.get("name", "")).strip()
                value = str(item.get("value", ""))
                if not category or not name or not value:
                    continue
                out.setdefault(category, []).append({**item, "name": name, "value": value})
            return out

        return {}

    if ext == ".csv":
        out: Dict[str, List[Payload]] = {}
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                category = (row.get("category") or "").strip()
                name = (row.get("name") or "").strip()
                value = row.get("value") or ""
                if not category or not name or not value:
                    continue
                out.setdefault(category, []).append({"name": name, "value": value})
        return out

    if ext in {".txt", ".tsv"} or ext == "":
        out: Dict[str, List[Payload]] = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip("\n")
                if not raw.strip() or raw.lstrip().startswith("#"):
                    continue
                if "|" in raw:
                    parts = raw.split("|", 2)
                else:
                    parts = raw.split("\t", 2)
                if len(parts) != 3:
                    continue
                category, name, value = parts
                category = category.strip()
                name = name.strip()
                value = value
                if not category or not name or not value:
                    continue
                out.setdefault(category, []).append({"name": name, "value": value})
        return out

    raise ValueError(f"Unsupported extra payloads file type: {ext}")


def _merge_extra_payloads(
    base: Dict[str, List[Payload]],
    extra: Dict[str, List[Payload]],
    *,
    similarity_threshold: float = 0.92,
) -> Tuple[Dict[str, List[Payload]], Dict[str, int]]:
    """Merge extra payloads into base, skipping duplicates and near-duplicates.

    - Does NOT remove anything from base.
    - Skips if name already exists in category.
    - Skips if normalized value already exists anywhere.
    - Skips if value is too similar (SequenceMatcher ratio) to an existing value in the same category.
    """

    merged: Dict[str, List[Payload]] = {k: list(v) for k, v in base.items()}

    existing_names_by_cat: Dict[str, set] = {
        cat: {str(p.get("name", "")) for p in payloads} for cat, payloads in merged.items()
    }

    existing_norm_values_global: set = set()
    existing_norm_values_by_cat: Dict[str, List[str]] = {}
    for cat, payloads in merged.items():
        norms: List[str] = []
        for p in payloads:
            value = str(p.get("value", ""))
            norm = _normalize_payload_value(value)
            existing_norm_values_global.add(norm)
            norms.append(norm)
        existing_norm_values_by_cat[cat] = norms

    stats = {
        "extra_total": 0,
        "added": 0,
        "skipped_duplicate_name": 0,
        "skipped_duplicate_value": 0,
        "skipped_too_similar": 0,
        "skipped_invalid": 0,
    }

    for category, payloads in extra.items():
        if not isinstance(payloads, list):
            continue
        merged.setdefault(category, [])
        existing_names_by_cat.setdefault(category, set())
        existing_norm_values_by_cat.setdefault(category, [])

        for payload in payloads:
            stats["extra_total"] += 1
            if not isinstance(payload, dict):
                stats["skipped_invalid"] += 1
                continue

            name = str(payload.get("name", "")).strip()
            value = str(payload.get("value", ""))
            if not name or not value:
                stats["skipped_invalid"] += 1
                continue

            if name in existing_names_by_cat[category]:
                stats["skipped_duplicate_name"] += 1
                continue

            norm = _normalize_payload_value(value)
            if norm in existing_norm_values_global:
                stats["skipped_duplicate_value"] += 1
                continue

            too_similar = False
            for existing_norm in existing_norm_values_by_cat[category]:
                if _similarity_ratio(norm, existing_norm) >= similarity_threshold:
                    too_similar = True
                    break
            if too_similar:
                stats["skipped_too_similar"] += 1
                continue

            merged[category].append({**payload, "name": name, "value": value})
            existing_names_by_cat[category].add(name)
            existing_norm_values_by_cat[category].append(norm)
            existing_norm_values_global.add(norm)
            stats["added"] += 1

    return merged, stats


def _audit_payloads(
    payloads_by_category: Dict[str, List[Payload]], *, similarity_threshold: float = 0.92
) -> Dict[str, int]:
    """Light audit for duplicates/near-duplicates (does not modify anything)."""

    duplicate_names = 0
    duplicate_values = 0
    near_duplicates = 0

    seen_values_global: set = set()
    for category, payloads in payloads_by_category.items():
        names = [str(p.get("name", "")) for p in payloads]
        duplicate_names += len(names) - len(set(names))

        norms = [_normalize_payload_value(str(p.get("value", ""))) for p in payloads]
        for norm in norms:
            if norm in seen_values_global:
                duplicate_values += 1
            else:
                seen_values_global.add(norm)

        # Quick near-duplicate scan within category
        for i in range(len(norms)):
            a = norms[i]
            for j in range(i + 1, len(norms)):
                b = norms[j]
                if a == b:
                    continue
                if _similarity_ratio(a, b) >= similarity_threshold:
                    near_duplicates += 1
                    break

    return {
        "duplicate_names": duplicate_names,
        "duplicate_values": duplicate_values,
        "near_duplicates": near_duplicates,
    }
