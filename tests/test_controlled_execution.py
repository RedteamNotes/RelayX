import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.execution import (
    ExecutionModuleSpec,
    ExecutionRequest,
    apply_execution_to_result,
    execute_path,
    render_execution,
)
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
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


class ControlledExecutionTests(unittest.TestCase):
    def test_dry_run_execution_does_not_dispatch_module(self):
        result = _result_with_http_path()
        run = execute_path(
            result,
            ExecutionRequest(path_id=result.paths[0].id, mode="dry-run"),
        )

        self.assertEqual(run["result"]["state"], "dry_run")
        self.assertEqual(run["actions"], [])
        self.assertFalse(run["execution"]["supported"])
        self.assertTrue(all(item["state"] != "fail" for item in run["guardrails"]))

    def test_blocked_path_fails_execution_guardrail(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_smb_blocked_finding()]
        result.paths = build_paths(result.findings)

        run = execute_path(result, ExecutionRequest(path_id=result.paths[0].id))

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "path_status" and item["state"] == "fail" for item in run["guardrails"]))
        self.assertTrue(any(item["key"] == "calculus_decision" and item["state"] == "fail" for item in run["guardrails"]))

    def test_confirmed_requires_confirmation_context(self):
        result = _result_with_smb_ready_path()
        run = execute_path(
            result,
            ExecutionRequest(path_id=result.paths[0].id, mode="confirmed"),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        failing = {item["key"] for item in run["guardrails"] if item["state"] == "fail"}
        self.assertIn("confirm_flag", failing)
        self.assertIn("operator", failing)
        self.assertIn("reason", failing)
        self.assertIn("audit_log", failing)

    def test_confirmed_non_ready_path_requires_explicit_acceptance(self):
        result = _result_with_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "audit.jsonl"
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized execution planning",
                    audit_log=str(audit_log),
                    scope=load_scope("ca01"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(
            any(
                item["key"] == "calculus_readiness" and item["state"] == "fail"
                for item in run["guardrails"]
            )
        )

    def test_confirmed_noop_writes_audit_log_and_stops_before_relay(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "relayx-execution.jsonl"
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized execution core test",
                    audit_log=str(audit_log),
                    scope=load_scope("filesrv01"),
                ),
            )
            rows = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(run["result"]["state"], "no_module_available")
        self.assertEqual([row["phase"] for row in run["adapter_lifecycle"]], ["prepare", "execute", "cleanup"])
        self.assertTrue(any(action["type"] == "adapter_execute" for action in run["actions"]))
        self.assertTrue(all(not action["network_action"] for action in run["actions"]))
        self.assertEqual(rows[0]["run_id"], run["run_id"])
        self.assertEqual(rows[0]["operator"], "redpen")

    def test_confirmed_execution_requires_explicit_scope(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized execution scope negative test",
                    audit_log=str(Path(tmp) / "relayx-execution.jsonl"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "confirmed_scope_required" and item["state"] == "fail" for item in run["guardrails"]))

    def test_lab_only_live_fixture_is_blocked_before_adapter_dispatch(self):
        result = _result_with_smb_ready_path()
        registry = {
            "lab_only_target_relay_fixture": ExecutionModuleSpec(
                key="lab_only_target_relay_fixture",
                label="Lab-only target relay adapter fixture",
                supported=False,
                lab_only=True,
                reason="Lab-only fixture is not registered.",
                adapter="lab_only_target_relay_fixture",
                network_action="lab_only_target_relay_fixture",
                credential_policy="synthetic_only",
                listener_policy="no_listener",
                target_families=("*",),
                source_capabilities=("*",),
            )
        }
        with tempfile.TemporaryDirectory() as tmp:
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized lab-only fixture negative test",
                    audit_log=str(Path(tmp) / "relayx-execution.jsonl"),
                    scope=load_scope("filesrv01"),
                    module="lab_only_target_relay_fixture",
                    module_registry=registry,
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "adapter_registered" and item["state"] == "fail" for item in run["guardrails"]))
        self.assertTrue(any(item["key"] == "lab_only_live_module_boundary" and item["state"] == "fail" for item in run["guardrails"]))
        self.assertFalse(run["adapter_lifecycle"])

    def test_registered_lab_only_fixture_is_blocked_before_dispatch(self):
        result = _result_with_smb_ready_path()
        registry = {
            "lab_only_offline_fixture": ExecutionModuleSpec(
                key="lab_only_offline_fixture",
                label="Lab-only offline fixture",
                supported=True,
                lab_only=True,
                reason="Lab-only fixture negative test.",
                adapter="offline_audit_record",
                network_action="none",
                credential_policy="none",
                listener_policy="none",
                target_families=("*",),
                source_capabilities=("*",),
            )
        }
        with tempfile.TemporaryDirectory() as tmp:
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized registered lab-only fixture negative test",
                    audit_log=str(Path(tmp) / "relayx-execution.jsonl"),
                    scope=load_scope("filesrv01"),
                    module="lab_only_offline_fixture",
                    module_registry=registry,
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "adapter_registered" and item["state"] == "pass" for item in run["guardrails"]))
        self.assertTrue(any(item["key"] == "lab_only_live_module_boundary" and item["state"] == "fail" for item in run["guardrails"]))
        self.assertFalse(run["adapter_lifecycle"])

    def test_module_timeout_cannot_exceed_execution_timebox(self):
        result = _result_with_smb_ready_path()
        registry = {
            "slow_fixture": ExecutionModuleSpec(
                key="slow_fixture",
                label="Slow fixture",
                supported=True,
                reason="Timeout negative test.",
                adapter="offline_audit_record",
                credential_policy="none",
                listener_policy="none",
                timeout_seconds=600,
                target_families=("*",),
                source_capabilities=("*",),
            )
        }
        with tempfile.TemporaryDirectory() as tmp:
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized timeout negative test",
                    audit_log=str(Path(tmp) / "relayx-execution.jsonl"),
                    scope=load_scope("filesrv01"),
                    module="slow_fixture",
                    module_registry=registry,
                    timebox_seconds=300,
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "execution_timeout" and item["state"] == "fail" for item in run["guardrails"]))

    def test_scope_and_noise_guardrails_block_execution(self):
        result = ScanResult.new(target_count=1, source_count=1)
        result.sources = [SourceAsset(host="srv01", capabilities={"spooler": True}, noise_limit=NoiseLevel.HIGH)]
        result.findings = [_http_candidate()]
        result.paths = build_paths(result.findings, sources=result.sources, max_noise=NoiseLevel.HIGH)

        run = execute_path(
            result,
            ExecutionRequest(
                path_id=result.paths[0].id,
                scope=load_scope("other-host"),
                max_noise=NoiseLevel.MEDIUM,
            ),
        )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "scope_target" and item["state"] == "fail" for item in run["guardrails"]))
        self.assertTrue(any(item["key"] == "noise_budget" and item["state"] == "fail" for item in run["guardrails"]))

    def test_apply_execution_to_result_records_evidence(self):
        result = _result_with_http_path()
        run = execute_path(result, ExecutionRequest(path_id=result.paths[0].id))
        annotated = apply_execution_to_result(result, run)
        evidence = {item.key: item for item in annotated.paths[0].evidence}

        self.assertEqual(evidence["relayx_execution_run"].value, "dry_run")
        self.assertEqual(evidence["relayx_execution_run"].raw["run_id"], run["run_id"])

    def test_render_execution_contains_guardrails_and_boundaries(self):
        result = _result_with_http_path()
        run = execute_path(result, ExecutionRequest(path_id=result.paths[0].id))
        rendered = render_execution(run)

        self.assertIn("RelayX Execution", rendered)
        self.assertIn("Guardrails", rendered)
        self.assertIn("Planned Steps", rendered)

    def test_cli_run_json_and_annotate_out(self):
        result = _result_with_http_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            output_file = root / "execution.json"
            annotated_file = root / "annotated.json"
            write_result(result, str(result_file))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "run",
                        "--result",
                        str(result_file),
                        "--path-id",
                        result.paths[0].id,
                        "--format",
                        "json",
                        "--out",
                        str(output_file),
                        "--annotate-out",
                        str(annotated_file),
                    ]
                )
            data = json.loads(output_file.read_text(encoding="utf-8"))
            annotated = json.loads(annotated_file.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["result"]["state"], "dry_run")
        evidence_keys = {item["key"] for item in annotated["paths"][0]["evidence"]}
        self.assertIn("relayx_execution_run", evidence_keys)


def _result_with_http_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_http_candidate(host="ca01")]
    result.paths = build_paths(result.findings)
    return result


def _result_with_smb_ready_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_smb_relayable_finding()]
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


def _smb_relayable_finding() -> Finding:
    return Finding(
        host="filesrv01",
        port=445,
        protocol="smb",
        name="smb_signing",
        status=Status.RELAYABLE,
        confidence=Confidence.HIGH,
        impact=Impact.MEDIUM,
        summary="SMB signing is not required.",
        evidence=[Evidence(EvidenceType.OBSERVED, "smb_signing_required", False, Confidence.HIGH)],
        fixes=["Require SMB signing."],
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
