import json
import subprocess
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import requests

from engine import ProbeClient, send_payload
from packs import PACKS, load_pack
from payload_io import _load_extra_payloads_file
from runner import ScanConfig, neutral_delivery, run_scan
from tests.fixture import fixture
from tests.parser_fixture import parser_response


class ResearchPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = fixture()
        cls.server, cls.url = cls.ctx.__enter__()
        cls.http = requests.Session()
        cls.http.trust_env = False

    @classmethod
    def tearDownClass(cls):
        cls.http.close()
        cls.ctx.__exit__(None, None, None)

    def run_pack(self, pack, baseline=True):
        return run_scan(ScanConfig(self.url + "research", interval=0, baseline=baseline), load_pack(pack))

    def probe(self, pack, index):
        return PACKS[pack]["probes"][index]

    def test_research_manifest_has_sources_and_fourteen_unique_deliveries(self):
        from engine import deliveries

        research = load_pack("research")
        self.assertEqual(sum(map(len, research.values())), 14)
        keys = []
        for probes in research.values():
            for probe in probes:
                self.assertTrue(probe["sources"] and probe["goal"] and probe["side_effects"])
                self.assertTrue(all(url.startswith("https://") for url in probe["sources"]))
                keys.append(json.dumps(list(deliveries("research", probe)), sort_keys=True, default=bytes.decode))
        self.assertEqual(len(set(keys)), 14)

    def test_duplicate_json_members_reach_fixture_in_original_order(self):
        result = self.run_pack("json_parsing")
        self.assertEqual(result["requests"], 7)
        for index in [0, 1]:
            probe = self.probe("json_parsing", index)
            capture = next(item for item in self.server.captures if item["body"] == probe["value"])
            pairs = json.loads(capture["body"], object_pairs_hook=list)
            self.assertEqual(len(pairs), 2)
            response = self.http.post(self.url + "json-parser", data=capture["body"].encode(), timeout=2)
            parsed = response.json()
            self.assertEqual(parsed["first_probe"], pairs[0][1])
            self.assertEqual(parsed["last_probe"], pairs[1][1])

    def test_json_escapes_are_transmitted_literally_not_reserialized(self):
        self.run_pack("json_parsing")
        for index in [2, 3]:
            value = self.probe("json_parsing", index)["value"]
            self.assertIn("\\u", value)
            self.assertTrue(any(item["body"] == value for item in self.server.captures))
            response = self.http.post(self.url + "json-parser", data=value.encode(), timeout=2)
            self.assertEqual(response.json()["last_probe"], "firestorm-marker")

    def test_invalid_json_is_rejected_without_becoming_a_waf_verdict(self):
        result = self.run_pack("json_parsing")
        rows = [row for row in result["rows"] if row["phase"] == "probe"]
        self.assertEqual([row["status"] for row in rows], [200, 200, 200, 200, 422, 422])
        for row in rows[-2:]:
            self.assertEqual(row["result"], "ambiguous")
            self.assertEqual(row["baseline_status"], 200)
            self.assertEqual(row["comparison"], "different_sample")
            self.assertEqual(row["confirmation"], "unconfirmed")
        nul = self.probe("json_parsing", 4)["value"]
        self.assertIn("\x00", nul)
        self.assertTrue(any(item["body"] == nul for item in self.server.captures))

    def test_xml_text_variants_parse_to_same_marker_without_execution(self):
        result = self.run_pack("xml_parsing")
        self.assertEqual(result["requests"], 5)
        rows = [row for row in result["rows"] if row["phase"] == "probe"]
        self.assertEqual(len({row["sample_sha256"] for row in rows[:3]}), 1)
        for probe in PACKS["xml_parsing"]["probes"]:
            response = self.http.post(self.url + "xml-parser", data=probe["value"].encode(), timeout=2)
            self.assertEqual(response.json()["text"], "firestorm-marker")
        self.assertEqual(rows[-1]["result"], "no_block_signal")
        self.assertTrue(all(row["confirmation"] == "unconfirmed" for row in rows))

    def test_xml_fixture_disables_dtds_before_parsing(self):
        body = '<!DOCTYPE probe [<!ENTITY marker "firestorm">]><probe>&marker;</probe>'
        status, result = parser_response("xml-parser", "POST", "", body, "application/xml")
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(result)["error"], "dtd_and_entities_disabled")

    def test_repeated_parameters_preserve_order_in_both_query_and_form(self):
        start = len(self.server.captures)
        result = self.run_pack("parameter_pollution", baseline=False)
        captured = self.server.captures[start:]
        self.assertEqual(result["requests"], 8)
        for index, probe in enumerate(PACKS["parameter_pollution"]["probes"]):
            get, post = captured[index * 2 : index * 2 + 2]
            self.assertEqual(
                parse_qsl(urlsplit(get["path"]).query), [tuple(pair) for pair in probe["parameters"]]
            )
            self.assertEqual(parse_qsl(post["body"]), [tuple(pair) for pair in probe["parameters"]])
            self.assertEqual(post["content_type"], "application/x-www-form-urlencoded")

    def test_parameter_controls_keep_duplicate_count_and_name_shape(self):
        pairs = self.probe("parameter_pollution", 0)["parameters"]
        control = neutral_delivery({"params": pairs})
        self.assertEqual(control["params"], [["q", "firestorm-control"], ["q", "firestorm-control"]])
        self.assertEqual(pairs[1][1], "firestorm-marker")
        result = self.run_pack("parameter_pollution")
        self.assertEqual(result["requests"], 14)
        self.assertEqual(sum(row["phase"] == "baseline" for row in result["rows"]), 6)

    def test_invalid_parameter_metadata_is_skipped_without_sending(self):
        client = ProbeClient(interval=0)
        try:
            for pairs in [None, [], [["q"]], [["q", 1]], "q=a&q=b", [["q", "x"]] * 17]:
                rows = send_payload(
                    client,
                    self.url,
                    "test",
                    {"name": "bad", "value": "marker", "method": "parameters", "parameters": pairs},
                )
                self.assertEqual(rows[0]["result"], "skipped")
            self.assertEqual(client.count, 0)
        finally:
            client.close()

    def test_import_preserves_repeated_parameter_metadata(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pairs.json"
            expected = self.probe("parameter_pollution", 0)
            path.write_text(json.dumps({"custom": [expected]}))
            loaded = _load_extra_payloads_file(path)
            self.assertEqual(loaded["custom"][0]["parameters"], expected["parameters"])

    def test_core_includes_research_and_stays_within_default_budget(self):
        result = self.run_pack("core")
        self.assertEqual(sum(map(len, load_pack("core").values())), 26)
        self.assertEqual(result["requests"], 59)
        self.assertEqual(result["stop_reason"], "completed")
        self.assertTrue(all(row["confirmation"] == "unconfirmed" for row in result["rows"]))

    def test_cli_selects_research_pack_and_records_every_delivery(self):
        result = subprocess.run(
            [
                sys.executable,
                "main.py",
                "--url",
                self.url + "research",
                "--pack",
                "research",
                "--interval",
                "0",
                "--plain",
                "--no-csv",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("26 requests", result.stdout)
        self.assertIn("UNCONFIRMED", result.stdout)


if __name__ == "__main__":
    unittest.main()
