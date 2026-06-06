import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from relayx.cli import main
from relayx.engine.operation_control import OperationControl, OperationControlError
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
from relayx.engine.source_validation import SourceCheckRequest, build_source_plan
from relayx.engine.validation import ValidationRequest, validate_path
from relayx.io import write_result
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, NoiseLevel, ScanResult, SourceAsset, Status
from relayx.net import ConnectResult


class OpsecScopeControlTests(unittest.TestCase):
    def test_confirmed_reprobe_is_blocked_outside_operation_window(self):
        result = _result_with_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            request = ValidationRequest(
                path_id=result.paths[0].id,
                mode="confirmed",
                confirm=True,
                operator="redpen",
                reason="authorized validation window test",
                audit_log=str(Path(tmp) / "audit.jsonl"),
                reprobe=True,
                operation_control=OperationControl.from_values(stop_before="2000-01-01T00:00:00+00:00"),
            )

            with patch("relayx.engine.validation.http.assess") as mocked:
                run = validate_path(result, request)

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(row["key"] == "operation_window" and row["state"] == "fail" for row in run["guardrails"]))
        mocked.assert_not_called()

    def test_dry_run_records_expired_window_without_active_failure(self):
        result = _result_with_http_path()
        run = validate_path(
            result,
            ValidationRequest(
                path_id=result.paths[0].id,
                mode="dry-run",
                operation_control=OperationControl.from_values(stop_before="2000-01-01T00:00:00+00:00"),
            ),
        )

        self.assertEqual(run["result"]["state"], "dry_run")
        self.assertTrue(any(row["key"] == "operation_window" and row["state"] == "warn" for row in run["guardrails"]))

    def test_runtime_window_closure_records_blocked_validation_run(self):
        result = _result_with_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "audit.jsonl"
            request = ValidationRequest(
                path_id=result.paths[0].id,
                mode="confirmed",
                confirm=True,
                operator="redpen",
                reason="authorized validation runtime window test",
                audit_log=str(audit_log),
                reprobe=True,
                operation_control=OperationControl.from_values(delay_seconds=1),
            )
            with patch("relayx.engine.validation.ensure_operation_window", side_effect=[None, OperationControlError("closed")]):
                with patch("relayx.engine.validation.time.sleep"):
                    with patch("relayx.engine.validation.http.assess") as mocked:
                        run = validate_path(result, request)
            audit_rows = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(row["key"] == "operation_window_runtime" for row in run["guardrails"]))
        self.assertEqual(audit_rows[0]["run_id"], run["run_id"])
        mocked.assert_not_called()

    def test_scan_records_operation_control_in_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "result.json"
            with patch("relayx.cli.assess_targets", return_value=[_http_candidate()]) as mocked:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = main(
                        [
                            "--no-banner",
                            "scan",
                            "--targets",
                            "ca01",
                            "--out",
                            str(output),
                            "--rate-limit",
                            "120",
                            "--stop-before",
                            "2099-01-01T00:00:00+00:00",
                        ]
                    )
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["metadata"]["operation_control"]["rate_limit"]["max_per_minute"], 120)
        self.assertTrue(data["metadata"]["expected_telemetry"])
        self.assertIn("operation_control", mocked.call_args.kwargs)

    def test_routes_authorized_connect_check_is_explicit_and_limited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources.json"
            targets = root / "targets.txt"
            output = root / "routes.json"
            sources.write_text(json.dumps({"sources": [{"host": "ws01", "subnets": ["10.20.0.0/16"]}]}), encoding="utf-8")
            targets.write_text("10.20.2.5\n", encoding="utf-8")

            with patch("relayx.engine.routes.tcp_connect", return_value=ConnectResult(open=True, error="")):
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = main(
                        [
                            "routes",
                            "--sources",
                            str(sources),
                            "--targets",
                            str(targets),
                            "--target-protocol",
                            "ldap",
                            "--connect-check",
                            "--format",
                            "json",
                            "--out",
                            str(output),
                        ]
                    )
            data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        check = data["routes"][0]["reachability_check"]
        self.assertEqual(check["method"], "authorized_direct_tcp_connect")
        self.assertEqual(check["network_action"], "tcp_connect_check")
        self.assertTrue(any("does not start or prove a pivot session" in item for item in check["limitations"]))
        self.assertTrue(data["operation_control"]["machine_output"]["banner_suppressed_for_machine_formats"])

    def test_source_plan_listener_callback_scope_contract(self):
        sources = [SourceAsset(host="ws01", capabilities={"webclient": True}, noise_limit=NoiseLevel.MEDIUM)]
        plan = build_source_plan(
            sources,
            "ws01",
            "webclient",
            SourceCheckRequest(
                max_noise=NoiseLevel.MEDIUM,
                scope=load_scope("ws01,listener01,callback01"),
                listener_host="listener01",
                callback_host="callback01",
            ),
        )

        self.assertEqual(plan["state"], "planned")
        self.assertTrue(all(row["state"] == "pass" for row in plan["scope_contract"]["guardrails"]))

    def test_source_plan_blocks_listener_callback_outside_scope(self):
        sources = [SourceAsset(host="ws01", capabilities={"webclient": True}, noise_limit=NoiseLevel.MEDIUM)]
        plan = build_source_plan(
            sources,
            "ws01",
            "webclient",
            SourceCheckRequest(
                max_noise=NoiseLevel.MEDIUM,
                scope=load_scope("ws01,listener01"),
                listener_host="listener01",
                callback_host="callback01",
            ),
        )

        self.assertEqual(plan["state"], "scope_blocked")
        self.assertTrue(any(row["key"] == "scope_callback" and row["state"] == "fail" for row in plan["scope_contract"]["guardrails"]))


def _result_with_http_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_http_candidate()]
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
        ],
    )


if __name__ == "__main__":
    unittest.main()
