import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.execution import ExecutionRequest, execute_path
from relayx.engine.modules import (
    build_module_plan,
    load_module_registry,
    module_inventory,
    render_module_inventory,
    render_module_plan,
)
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
from relayx.io import write_result
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, ScanResult, Status


FIXTURE_MODULE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "execution_modules"


class ExecutionModuleTests(unittest.TestCase):
    def test_default_registry_contains_offline_audit_adapter(self):
        registry = load_module_registry()
        inventory = module_inventory(registry)
        keys = {module["key"] for module in inventory["modules"]}

        self.assertIn("noop", keys)
        self.assertIn("relayx_audit_record", keys)
        self.assertIn("ntlmrelayx_compat", keys)
        self.assertIn("offline_audit_record", {adapter["key"] for adapter in inventory["adapter_sdk"]["adapters"]})
        self.assertTrue(registry["relayx_audit_record"].supported)
        self.assertEqual(registry["relayx_audit_record"].network_action, "none")

    def test_manifest_directory_overrides_and_loads_modules(self):
        registry = load_module_registry(str(FIXTURE_MODULE_DIR), include_defaults=False)

        self.assertEqual(set(registry), {"lab_only_target_relay_fixture", "ntlmrelayx_compat", "relayx_audit_record"})
        self.assertEqual(registry["relayx_audit_record"].version, "0.5.4-fixture")
        self.assertFalse(registry["ntlmrelayx_compat"].supported)
        self.assertTrue(registry["lab_only_target_relay_fixture"].lab_only)

    def test_missing_manifest_path_raises_clear_error(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            load_module_registry("/not/a/relayx/module/path", include_defaults=False)

    def test_module_plan_marks_offline_adapter_ready_for_candidate_ready_path(self):
        result = _result_with_smb_ready_path()
        plan = build_module_plan(
            result,
            result.paths[0].id,
            load_module_registry(),
            module_key="relayx_audit_record",
        )
        row = plan["modules"][0]

        self.assertEqual(plan["decision"], "candidate_ready")
        self.assertEqual(row["state"], "ready")
        self.assertTrue(row["applicable"])
        self.assertTrue(row["executable"])
        self.assertFalse(row["warnings"])

    def test_module_plan_marks_http_path_as_needing_validation(self):
        result = _result_with_http_path()
        plan = build_module_plan(
            result,
            result.paths[0].id,
            load_module_registry(),
            module_key="relayx_audit_record",
        )
        row = plan["modules"][0]

        self.assertEqual(plan["decision"], "candidate_needs_validation")
        self.assertEqual(row["state"], "needs_validation_or_calibration")
        self.assertFalse(row["executable"])

    def test_module_plan_keeps_ntlmrelayx_boundary_unsupported(self):
        result = _result_with_smb_ready_path()
        plan = build_module_plan(
            result,
            result.paths[0].id,
            load_module_registry(),
            module_key="ntlmrelayx_compat",
        )
        row = plan["modules"][0]

        self.assertEqual(row["state"], "unsupported")
        self.assertFalse(row["executable"])
        self.assertIn("future_relay_module", row["warnings"][0])

    def test_lab_only_fixture_is_not_executable_or_registered(self):
        result = _result_with_smb_ready_path()
        plan = build_module_plan(
            result,
            result.paths[0].id,
            load_module_registry(str(FIXTURE_MODULE_DIR), include_defaults=False),
            module_key="lab_only_target_relay_fixture",
        )
        row = plan["modules"][0]

        self.assertEqual(row["state"], "unsupported")
        self.assertTrue(row["module"]["lab_only"])
        self.assertFalse(row["adapter_sdk"]["registered"])
        self.assertIn("adapter_contract", row["evidence_capture"])

    def test_confirmed_offline_adapter_writes_audit_without_network_action(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "execution.jsonl"
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized offline audit record",
                    audit_log=str(audit_log),
                    module="relayx_audit_record",
                    scope=load_scope("filesrv01"),
                ),
            )
            rows = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(run["result"]["state"], "executed_offline")
        self.assertEqual(run["actions"][0]["adapter"], "offline_audit_record")
        self.assertFalse(run["actions"][0]["network_action"])
        self.assertEqual(run["execution_contract"]["timeout_behavior"], "fail_closed")
        self.assertIn("adapter_lifecycle", run["execution_contract"]["evidence_capture"])
        self.assertEqual(rows[0]["result"]["state"], "executed_offline")

    def test_empty_registry_does_not_fall_back_to_builtins(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "execution.jsonl"
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized empty registry test",
                    audit_log=str(audit_log),
                    module="relayx_audit_record",
                    module_registry={},
                    scope=load_scope("filesrv01"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(item["key"] == "module_registered" and item["state"] == "fail" for item in run["guardrails"]))

    def test_renderers_include_module_states(self):
        inventory = module_inventory(load_module_registry(), module_key="relayx_audit_record")
        plan = build_module_plan(
            _result_with_smb_ready_path(),
            "PX-0001",
            load_module_registry(),
            module_key="relayx_audit_record",
        )

        self.assertIn("RelayX Execution Modules", render_module_inventory(inventory))
        self.assertIn("state=ready", render_module_plan(plan))

    def test_cli_modules_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "modules.json"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "modules",
                        "--manifests",
                        str(FIXTURE_MODULE_DIR),
                        "--no-defaults",
                        "--format",
                        "json",
                        "--out",
                        str(out),
                    ]
                )
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["module_count"], 3)

    def test_cli_module_plan_json(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            out = root / "module-plan.json"
            write_result(result, str(result_file))
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "module-plan",
                        "--result",
                        str(result_file),
                        "--path-id",
                        result.paths[0].id,
                        "--module",
                        "relayx_audit_record",
                        "--format",
                        "json",
                        "--out",
                        str(out),
                    ]
                )
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["modules"][0]["state"], "ready")

    def test_cli_run_with_fixture_manifest_uses_offline_adapter(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            out = root / "execution.json"
            audit_log = root / "audit.jsonl"
            write_result(result, str(result_file))
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "run",
                        "--result",
                        str(result_file),
                        "--path-id",
                        result.paths[0].id,
                        "--module",
                        "relayx_audit_record",
                        "--manifests",
                        str(FIXTURE_MODULE_DIR),
                        "--mode",
                        "confirmed",
                        "--confirm",
                        "--operator",
                        "redpen",
                        "--reason",
                        "authorized fixture-backed offline adapter",
                        "--audit-log",
                        str(audit_log),
                        "--scope",
                        "filesrv01",
                        "--format",
                        "json",
                        "--out",
                        str(out),
                    ]
                )
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(data["result"]["state"], "executed_offline")
        self.assertFalse(data["actions"][0]["network_action"])


def _result_with_smb_ready_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_smb_relayable_finding()]
    result.paths = build_paths(result.findings)
    return result


def _result_with_http_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_http_candidate()]
    result.paths = build_paths(result.findings)
    return result


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


def _http_candidate() -> Finding:
    return Finding(
        host="ca01",
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


if __name__ == "__main__":
    unittest.main()
