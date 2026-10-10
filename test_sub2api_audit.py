import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sub2api_audit as audit


ROOT = Path(__file__).parent


class StaticAuditTests(unittest.TestCase):
    def findings_by_rule(self, directory, expected_files=1):
        findings, files = audit.analyze_source(str(directory))
        self.assertEqual(files, expected_files)
        return {item["rule"]: item for item in findings}

    def test_vulnerable_fixture_reports_expected_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "vulnerable.go"
            source.write_text((ROOT / "testdata" / "easypay_vulnerable.go").read_text(encoding="utf-8"), encoding="utf-8")
            findings = self.findings_by_rule(Path(temp))
        self.assertEqual(findings["A"]["status"], audit.RISK)
        self.assertEqual(findings["B1"]["status"], audit.RISK)
        self.assertEqual(findings["B2"]["status"], audit.RISK)
        self.assertEqual(findings["C"]["status"], audit.RISK)

    def test_safe_fixture_reports_mitigations(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "safe.go"
            source.write_text((ROOT / "testdata" / "easypay_safe.go").read_text(encoding="utf-8"), encoding="utf-8")
            findings = self.findings_by_rule(Path(temp))
        self.assertEqual(findings["A"]["status"], audit.MITIGATED)
        self.assertEqual(findings["B1"]["status"], audit.MITIGATED)
        self.assertEqual(findings["B2"]["status"], audit.MITIGATED)
        self.assertEqual(findings["C"]["status"], audit.MITIGATED)

    def test_comments_do_not_trigger_function_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "comment.go"
            source.write_text(
                "package demo\n// func easyPaySign(params map[string]string, key string) string { return \"\" }\n",
                encoding="utf-8",
            )
            findings, files = audit.analyze_source(temp)
        self.assertEqual(files, 1)
        self.assertEqual(findings, [])


class UtilityTests(unittest.TestCase):
    def test_target_url_normalizes_base_path(self):
        self.assertEqual(audit._target_url("http://127.0.0.1:8080/app/", "/v1/models"), "http://127.0.0.1:8080/app/v1/models")
        with self.assertRaises(ValueError):
            audit._target_url("http://127.0.0.1:8080/?x=1", "/health")

    def test_explicit_success_requires_structured_positive_signal(self):
        self.assertTrue(audit._explicit_success(json.dumps({"success": True})))
        self.assertTrue(audit._explicit_success(json.dumps({"code": 0, "message": "success"})))
        self.assertFalse(audit._explicit_success("200 OK"))
        self.assertFalse(audit._explicit_success(json.dumps({"success": False, "message": "error"})))
        self.assertFalse(audit._explicit_success(json.dumps({"status": "success", "error": "invalid signature"})))

    def test_signature_rejection_requires_signature_and_rejection(self):
        self.assertTrue(audit._explicit_signature_rejection(400, '{"error":"invalid signature"}'))
        self.assertFalse(audit._explicit_signature_rejection(200, '{"message":"request accepted"}'))

    def test_gui_run_claim_is_single_use(self):
        audit.STATE.update(running=False, mode=None, target=None)
        cfg = {"mode": "static", "target": "http://127.0.0.1:8080"}
        self.assertTrue(audit._claim_gui_run(cfg))
        self.assertFalse(audit._claim_gui_run(cfg))
        audit._finish_gui_run()
        self.assertTrue(audit._claim_gui_run(cfg))
        audit._finish_gui_run()

    def test_scope_allows_private_and_rejects_remote_without_flag(self):
        with mock.patch.object(audit, "target_is_local", return_value=(True, "127.0.0.1")):
            self.assertTrue(audit.enforce_scope("http://127.0.0.1:8080"))
        with mock.patch.object(audit, "target_is_local", return_value=(False, "example.test")):
            self.assertFalse(audit.enforce_scope("https://example.test"))
            self.assertTrue(audit.enforce_scope("https://example.test", allow_remote=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
