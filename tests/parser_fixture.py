"""Bounded parser observations for local tests; never evaluate marker contents."""

import json
from urllib.parse import parse_qsl
from xml.etree import ElementTree


class ObjectPairs(list):
    """Distinguish JSON objects from arrays while retaining duplicate members."""


def parser_response(case, method, query, raw, content_type):
    if len(raw.encode()) > 8192:
        return 413, json.dumps({"error": "fixture_body_limit"})
    if case == "research":
        case = (
            "json-parser"
            if content_type.startswith("application/json")
            else "xml-parser"
            if content_type.startswith("application/xml")
            else "parameters"
        )
    if case == "json-parser":
        try:
            pairs = json.loads(raw, object_pairs_hook=ObjectPairs)
            if not isinstance(pairs, ObjectPairs):
                raise ValueError("expected object")
        except (ValueError, RecursionError):
            return 422, json.dumps({"error": "invalid_json", "policy": "stdlib-json"})
        values = [value for key, value in pairs if key == "probe"]
        summary = {
            "pairs": pairs,
            "first_probe": values[0] if values else None,
            "last_probe": values[-1] if values else None,
            "policy": "preserve_all_members",
        }
    elif case == "xml-parser":
        # These tests need text representations, never DTDs or entity expansion.
        if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
            return 422, json.dumps({"error": "dtd_and_entities_disabled"})
        try:
            root = ElementTree.fromstring(raw)
        except (ElementTree.ParseError, RecursionError):
            return 422, json.dumps({"error": "invalid_xml"})
        summary = {"tag": root.tag, "text": "".join(root.itertext()), "policy": "stdlib-elementtree-no-dtd"}
    else:
        pairs = parse_qsl(query if method == "GET" else raw, keep_blank_values=True)
        values = [value for key, value in pairs if key == "q"]
        summary = {
            "pairs": pairs,
            "first_q": values[0] if values else None,
            "last_q": values[-1] if values else None,
            "policy": "ordered_pairs_no_array_coercion",
        }
    return 200, json.dumps(summary, sort_keys=True, ensure_ascii=False)
