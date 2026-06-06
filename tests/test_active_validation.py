import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from relayx.cli import main
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
from relayx.engine.validation import ValidationRequest, render_validation, validate_path
from relayx.io import write_result
from relayx.models import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Impact,
    NoiseLevel,
    ScanResult,
    SourceAsset,
    Status,
)


class ActiveValidationTests(unittest.TestCase):
    def test_dry_run_validation_does_not_execute_actions(self):
        result = _result_with_generic_http_path()
        run = validate_path(
            result,
            ValidationRequest(path_id=result.paths[0].id, mode="dry-run"),
        )

        self.assertEqual(run["result"]["state"], "dry_run")
        self.assertEqual(run["actions"], [])
        self.assertTrue(all(item["state"] == "pass" for item in run["guardrails"]))

    def test_blocked_path_fails_guardrail(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_smb_blocked_finding()]
        result.paths = build_paths(result.findings)

        run = validate_path(
            result,
            ValidationRequest(path_id=result.paths[0].id, mode="dry-run"),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "path_status" and item["state"] == "fail" for item in run["guardrails"]))

    def test_confirmed_requires_confirm_operator_reason_and_audit(self):
        result = _result_with_generic_http_path()
        run = validate_path(
            result,
            ValidationRequest(path_id=result.paths[0].id, mode="confirmed"),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        failing = {item["key"] for item in run["guardrails"] if item["state"] == "fail"}
        self.assertIn("confirm_flag", failing)
        self.assertIn("operator", failing)
        self.assertIn("reason", failing)
        self.assertIn("audit_log", failing)

    def test_confirmed_noop_writes_audit_log(self):
        result = _result_with_generic_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "relayx-audit.jsonl"
            run = validate_path(
                result,
                ValidationRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized validation",
                    audit_log=str(audit_log),
                ),
            )
            rows = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(run["result"]["state"], "confirmed_noop")
        self.assertEqual(rows[0]["run_id"], run["run_id"])
        self.assertEqual(rows[0]["operator"], "redpen")

    def test_auth_validation_requires_confirmed_reprobe(self):
        result = _result_with_generic_http_path()
        run = validate_path(
            result,
            ValidationRequest(path_id=result.paths[0].id, mode="armed", auth_validation=True),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(
            any(
                item["key"] == "auth_validation_requires_confirmed_reprobe"
                and item["state"] == "fail"
                for item in run["guardrails"]
            )
        )

    def test_scope_guardrail_blocks_out_of_scope_target(self):
        result = _result_with_generic_http_path()
        run = validate_path(
            result,
            ValidationRequest(
                path_id=result.paths[0].id,
                mode="dry-run",
                scope=load_scope("other-host"),
            ),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "scope_target" and item["state"] == "fail" for item in run["guardrails"]))

    def test_noise_budget_blocks_high_noise_path(self):
        result = ScanResult.new(target_count=1, source_count=1)
        result.sources = [SourceAsset(host="srv01", capabilities={"spooler": True}, noise_limit=NoiseLevel.HIGH)]
        result.findings = [_http_candidate()]
        result.paths = build_paths(result.findings, sources=result.sources, max_noise=NoiseLevel.HIGH)

        run = validate_path(
            result,
            ValidationRequest(path_id=result.paths[0].id, max_noise=NoiseLevel.MEDIUM),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "noise_budget" and item["state"] == "fail" for item in run["guardrails"]))

    def test_confirmed_reprobe_calls_target_oracle(self):
        result = _result_with_generic_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = str(Path(tmp) / "audit.jsonl")
            with patch("relayx.engine.validation.http.assess", return_value=[_http_candidate(host="ca01")]) as mocked:
                run = validate_path(
                    result,
                    ValidationRequest(
                        path_id=result.paths[0].id,
                        mode="confirmed",
                        confirm=True,
                        operator="redpen",
                        reason="authorized target reprobe",
                        audit_log=audit_log,
                        reprobe=True,
                        timeout=1.0,
                    ),
                )

        self.assertEqual(run["result"]["state"], "observed")
        self.assertEqual(run["actions"][0]["type"], "target_reprobe")
        mocked.assert_called_once()

    def test_render_validation_contains_guardrails(self):
        result = _result_with_generic_http_path()
        run = validate_path(result, ValidationRequest(path_id=result.paths[0].id))
        rendered = render_validation(run)

        self.assertIn("RelayX Validation", rendered)
        self.assertIn("Guardrails", rendered)

    def test_cli_validate_json_output(self):
        result = _result_with_generic_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            output_file = root / "validation.json"
            write_result(result, str(result_file))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "validate",
                        "--result",
                        str(result_file),
                        "--path-id",
                        result.paths[0].id,
                        "--format",
                        "json",
                        "--out",
                        str(output_file),
                    ]
                )
            data = json.loads(output_file.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["result"]["state"], "dry_run")


def _result_with_generic_http_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_http_candidate(host="ca01")]
    result.paths = build_paths(result.findings)
    return result


def _http_candidate(host: str = "ca01") -> Finding:
    return Finding(
        host=host,
        port=80,
        protocol="http",
        name="adcs_web_enrollment",
        status=Status.CANDIDATE,
        confidence=Confidence.HIGH,
        impact=Impact.HIGH,
        summary="HTTP endpoint advertises NTLM.",
        evidence=[
            Evidence(EvidenceType.OBSERVED, "http_status", 401, Confidence.HIGH),
            Evidence(EvidenceType.OBSERVED, "ntlm_type2_challenge", True, Confidence.HIGH),
            Evidence(EvidenceType.INFERRED, "relayx_response_classification", "not_performed", Confidence.LOW),
        ],
    )


def _smb_blocked_finding() -> Finding:
    return Finding(
        host="filesrv01",
        port=445,
        protocol="smb",
        name="smb_signing",
        status=Status.BLOCKED,
        confidence=Confidence.HIGH,
        impact=Impact.INFO,
        summary="SMB signing is required.",
        evidence=[Evidence(EvidenceType.OBSERVED, "smb_signing_required", True, Confidence.HIGH)],
        blockers=["SMB signing required"],
    )


if __name__ == "__main__":
    unittest.main()
