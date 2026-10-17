import csv
import io
import threading
import unittest

from packs import PACKS, legacy_corpus, load_pack
from payloads import PAYLOADS
from runner import ScanConfig, csv_text, run_scan
from tests.fixture import fixture


class BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = fixture()
        cls.server, cls.url = cls.ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def run_pack(self, path="", corpus=None, **kwargs):
        corpus = corpus or {"lab": [{"name": "marker", "value": "firestorm-marker"}]}
        return run_scan(ScanConfig(self.url + path, interval=0, **kwargs), corpus)

    def test_controls_are_reused_only_within_same_delivery_profile(self):
        corpus = {"lab": [{"name": "a", "value": "a"}, {"name": "b", "value": "b"}]}
        result = self.run_pack(corpus=corpus)
        self.assertEqual(result["requests"], 9)
        rows = result["rows"]
        self.assertEqual(sum(row["phase"] == "baseline" for row in rows), 3)
        self.assertTrue(all(row["comparison"] == "same_sample" for row in rows if row["phase"] == "probe"))
        self.assertTrue(all(row["confirmation"] == "unconfirmed" for row in rows))

    def test_difference_does_not_confirm_exploit(self):
        result = self.run_pack("marker")
        probes = [row for row in result["rows"] if row["phase"] == "probe"]
        self.assertTrue(all(row["comparison"] == "different_sample" for row in probes))
        self.assertTrue(all(row["result"] == "no_block_signal" for row in probes))

    def test_denied_control_is_inconclusive(self):
        result = self.run_pack("mixed")
        get = next(row for row in result["rows"] if row["phase"] == "probe")
        self.assertEqual(get["baseline_status"], 403)
        self.assertEqual(get["comparison"], "baseline_inconclusive")

    def test_truncated_samples_never_claim_match(self):
        result = self.run_pack("large")
        self.assertTrue(
            all(row["comparison"] == "incomplete_sample" for row in result["rows"] if row["phase"] == "probe")
        )

    def test_rate_limited_control_stops_before_probe(self):
        result = self.run_pack("rate")
        self.assertEqual(result["requests"], 1)
        self.assertEqual(result["rows"][0]["phase"], "baseline")
        self.assertEqual(result["stop_reason"], "rate_limited")

    def test_baseline_consumes_request_budget(self):
        result = self.run_pack(max_requests=1)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["phase"], "baseline")
        self.assertEqual(result["stop_reason"], "budget_reached")

    def test_operator_cancellation_preserves_completed_rows(self):
        cancel = threading.Event()
        result = run_scan(
            ScanConfig(self.url, interval=0), load_pack("core"), on_row=lambda *_: cancel.set(), cancel=cancel
        )
        self.assertEqual(result["requests"], 1)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["stop_reason"], "cancelled")

    def test_keyboard_interrupt_keeps_rows_for_export(self):
        def interrupt(*_):
            raise KeyboardInterrupt

        result = run_scan(ScanConfig(self.url, interval=0), load_pack("core"), on_row=interrupt)
        self.assertEqual(result["stop_reason"], "cancelled")
        self.assertEqual(len(list(csv.DictReader(io.StringIO(csv_text(result["rows"]))))), 1)

    def test_no_baseline_mode_is_explicit(self):
        result = self.run_pack(baseline=False)
        self.assertEqual(result["requests"], 3)
        self.assertTrue(all(row["comparison"] == "not_collected" for row in result["rows"]))

    def test_distinct_field_names_get_distinct_controls(self):
        corpus = {
            "lab": [{"name": "q", "value": "x"}],
            "path_traversal_lfi": [{"name": "file", "value": "x"}],
        }
        result = self.run_pack(corpus=corpus)
        self.assertEqual(result["requests"], 12)

    def test_each_reviewed_probe_has_controlled_local_scenario(self):
        for pack, info in PACKS.items():
            if pack == "demo":
                continue
            for probe in info["probes"]:
                with self.subTest(probe=probe["name"]):
                    self.assertTrue(probe["goal"] and probe["side_effects"])
                    result = self.run_pack(probe["scenario"], {pack: [probe]})
                    probes = [row for row in result["rows"] if row["phase"] == "probe"]
                    self.assertTrue(probes)
                    self.assertTrue(all(row["status"] in {200, 400, 413, 422} for row in probes))
                    self.assertTrue(all(row["confirmation"] == "unconfirmed" for row in probes))

    def test_unicode_and_encoding_variants_normalize_to_same_fixture_body(self):
        for values in (PACKS["normalization"]["probes"][:2], PACKS["normalization"]["probes"][2:]):
            result = self.run_pack("normalization", {"normalization": values})
            probes = [row for row in result["rows"] if row["phase"] == "probe"]
            self.assertEqual(len({row["sample_sha256"] for row in probes}), 1)

    def test_json_type_boundaries_are_application_errors_not_waf_verdicts(self):
        for probe in PACKS["boundaries"]["probes"][1:3]:
            result = self.run_pack("boundary", {"boundaries": [probe]})
            row = next(row for row in result["rows"] if row["phase"] == "probe")
            self.assertEqual(row["status"], 422)
            self.assertEqual(row["baseline_status"], 200)
            self.assertEqual(row["result"], "ambiguous")
            self.assertEqual(row["comparison"], "different_sample")

    def test_legacy_opt_in_is_deduplicated_without_modifying_source(self):
        before = sum(map(len, PAYLOADS.values()))
        legacy = legacy_corpus()
        self.assertLess(sum(map(len, legacy.values())), before)
        self.assertEqual(before, 767)
        self.assertEqual(sum(map(len, load_pack("core").values())), 26)


if __name__ == "__main__":
    unittest.main()
