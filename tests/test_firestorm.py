import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import main
from payload_io import _load_extra_payloads_file, _merge_extra_payloads
from tests.fixture import fixture


class Classification(unittest.TestCase):
    def test_status_is_never_confirmation(self):
        cases = {
            200: "no_block_signal",
            204: "no_block_signal",
            302: "redirect",
            401: "ambiguous",
            403: "ambiguous",
            406: "ambiguous",
            404: "ambiguous",
            429: "rate_limited",
            500: "server_error",
            503: "server_error",
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                self.assertEqual(main.detect_blocked(code, "")[0], expected)

    def test_custom_codes_and_precedence(self):
        self.assertEqual(main.detect_blocked(418, "", {418})[0], "block_signal")
        self.assertEqual(main.detect_blocked(418, "")[0], "ambiguous")
        for code, result in [(429, "rate_limited"), (503, "server_error"), (302, "redirect")]:
            self.assertEqual(main.detect_blocked(code, "request blocked", {code})[0], result)

    def test_body_is_only_signal(self):
        self.assertEqual(
            main.detect_blocked(200, "Cloudflare SQL injection XSS waf blocked")[0], "no_block_signal"
        )
        result, reason = main.detect_blocked(200, "REQUEST BLOCKED")
        self.assertEqual(result, "block_signal")
        self.assertIn("reflection", reason)

    def test_target_scope(self):
        for url in ["http://127.0.0.1:8765/", "https://[::1]/lab"]:
            self.assertEqual(main.validate_target(url), url)
        for url in [
            "http://example.com",
            "http://localhost",
            "file:///etc/passwd",
            "http://u:p@127.0.0.1",
            "http://127.0.0.1/?q=x",
            "http://127.0.0.1/#x",
            "http://127.0.0.1:99999",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                main.validate_target(url)
        main.validate_target("https://authorized.invalid/lab", True)

    def test_invalid_options_fail_closed(self):
        for options in [
            ["--block-status", "oops"],
            ["--block-status", "700"],
            ["--timeout", "nan"],
            ["--interval", "inf"],
            ["--max-requests", "0"],
        ]:
            with (
                self.subTest(options=options),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                main.parse_args(["--url", "http://127.0.0.1", *options])

    def test_audit_needs_no_target(self):
        self.assertTrue(main.parse_args(["--audit-payloads"]).audit_payloads)


class LocalHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = fixture()
        cls.server, cls.url = cls.ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def setUp(self):
        self.client = main.ProbeClient(timeout=1, interval=0, max_requests=100)
        self.addCleanup(self.client.close)

    def observe(self, case, custom=None):
        return self.client.observe(self.url + case, "fixture", {"name": case}, "GET", {}, custom)

    def test_real_response_matrix(self):
        for case, result in [
            ("ok", "no_block_signal"),
            ("deny", "ambiguous"),
            ("signal", "block_signal"),
            ("vendor", "no_block_signal"),
            ("error", "server_error"),
            ("custom", "block_signal"),
        ]:
            with self.subTest(case=case):
                row = self.observe(case, {418})
                self.assertEqual(row["result"], result)
                self.assertEqual(row["confirmation"], "unconfirmed")

    def test_redirect_never_contacts_second_server(self):
        with fixture() as (destination, url):
            self.server.redirect_to = url
            self.assertEqual(self.observe("redirect")["result"], "redirect")
            self.assertEqual(destination.hits, [])

    def test_mixed_methods_preserve_details(self):
        rows = main.send_payload(
            self.client, self.url + "mixed", "fixture", {"name": "mixed", "value": "test"}
        )
        self.assertEqual([r["status"] for r in rows], [403, 200, 200])
        self.assertEqual([r["result"] for r in rows], ["ambiguous", "no_block_signal", "no_block_signal"])

    def test_rate_limit_stops_remaining_deliveries(self):
        start = len(self.server.hits)
        rows = main.send_payload(self.client, self.url + "rate", "fixture", {"name": "rate", "value": "test"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(self.server.hits) - start, 1)
        self.assertEqual(self.observe("ok")["result"], "skipped")

    def test_partial_body_retains_status_evidence(self):
        row = self.observe("broken")
        self.assertEqual(row["status"], 403)
        self.assertEqual(row["result"], "ambiguous")
        self.assertTrue(row["body_truncated"])
        self.assertIn("body read failed", row["reason"])

    def test_rate_limit_with_broken_body_still_stops(self):
        row = self.observe("ratebroken")
        self.assertEqual(row["result"], "rate_limited")
        self.assertTrue(self.client.stopped)
        self.assertEqual(self.observe("ok")["result"], "skipped")

    def test_timeout_is_not_block(self):
        self.client.timeout = 0.02
        self.assertEqual(self.observe("slow")["result"], "transport_error")

    def test_budget_is_per_request(self):
        self.client.max_requests = 2
        rows = main.send_payload(self.client, self.url, "fixture", {"name": "ok", "value": "ok"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.client.count, 2)
        self.assertEqual(self.observe("ok")["result"], "skipped")

    def test_pacing(self):
        self.client.interval = 0.06
        self.observe("ok")
        start = self.client.last_start
        self.observe("ok")
        self.assertGreaterEqual(self.client.last_start - start, 0.055)

    def test_body_bound(self):
        row = self.observe("large")
        self.assertEqual(row["body_bytes_sampled"], main.BODY_LIMIT)
        self.assertTrue(row["body_truncated"])

    def test_delivery_types_and_no_path_escape(self):
        start = len(self.server.hits)
        for payload in [
            {"header_name": "X-Probe"},
            {"method": "cookie"},
            {"content_type": "json"},
            {"content_type": "xml"},
            {"method": "path"},
        ]:
            rows = main.send_payload(
                self.client, self.url + "fixed", "fixture", {"name": "probe", "value": "../other", **payload}
            )
            self.assertTrue(all(r["status"] == 200 for r in rows))
        self.assertTrue(all(path.startswith("/fixed") for _, path in self.server.hits[start:]))

    def test_unsupported_sends_nothing(self):
        start = self.client.count
        for payload in [
            {"raw_request": True},
            {"header_name": "Host"},
            {"header_name": "Content-Length"},
            {"method": "DELETE"},
        ]:
            row = main.send_payload(
                self.client, self.url, "fixture", {"name": "probe", "value": "x", **payload}
            )[0]
            self.assertEqual(row["result"], "skipped")
        self.assertEqual(self.client.count, start)

    def test_invalid_metadata_is_skipped_before_network(self):
        for metadata in ({"header_name": []}, {"content_type": {}}, {"method": []}):
            rows = main.send_payload(
                self.client, self.url, "fixture", {"name": "invalid", "value": "x", **metadata}
            )
            self.assertEqual(rows[0]["result"], "skipped")
        self.assertEqual(self.client.count, 0)

    def test_invalid_header_is_transport_error(self):
        rows = main.send_payload(
            self.client, self.url, "fixture", {"name": "bad", "value": "x\r\ny", "header_name": "X-Probe"}
        )
        self.assertEqual(rows[0]["result"], "transport_error")

    def test_cli_and_csv_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.csv"
            run = subprocess.run(
                [
                    sys.executable,
                    "main.py",
                    "--url",
                    self.url,
                    "--payloads-only",
                    "examples/demo.json",
                    "--block-status",
                    "418",
                    "--interval",
                    "0",
                    "--csv",
                    str(report),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(run.returncode, 1, run.stderr)
            with report.open() as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 25)
            self.assertEqual(sum(row["phase"] == "baseline" for row in rows), 3)
            self.assertEqual(rows[-1]["result"], "rate_limited")
            self.assertIn("No effectiveness score", run.stdout)
            self.assertNotIn("POTENTIAL VULNERABILITIES", run.stdout)
            self.assertTrue(all(r["confirmation"] == "unconfirmed" for r in rows))


class InputOutput(unittest.TestCase):
    def test_metadata_survives_json_import_and_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probes.json"
            path.write_text(
                json.dumps({"demo": [{"name": "header", "value": "hello", "header_name": "X-Probe"}]})
            )
            loaded = _load_extra_payloads_file(path)
            merged, stats = _merge_extra_payloads({}, loaded)
            self.assertEqual(merged["demo"][0]["header_name"], "X-Probe")
            self.assertEqual(stats["added"], 1)

    def test_csv_formula_neutralized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            row = dict.fromkeys(main.FIELDS)
            row.update(category="=1+1", name=" @SUM(1)", result="skipped")
            with contextlib.redirect_stdout(io.StringIO()):
                main.print_report([row], path)
            with path.open() as handle:
                saved = next(csv.DictReader(handle))
            self.assertTrue(saved["category"].startswith("'"))
            self.assertTrue(saved["name"].startswith("'"))


if __name__ == "__main__":
    unittest.main()
