import json
import tempfile
import unittest
from pathlib import Path

from relayx.engine.adapter_sdk import default_adapter_registry
from relayx.engine.execution import ExecutionModuleSpec, ExecutionRequest, execute_path
from relayx.engine.modules import build_module_plan, load_module_registry
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, ScanResult, Status


class ExecutionAdapterSDKTests(unittest.TestCase):
    def test_default_adapter_registry_describes_safe_adapters(self):
        inventory = default_adapter_registry().describe()
        adapters = {row["key"]: row for row in inventory["adapters"]}

        self.assertEqual(inventory["version"], 1)
        self.assertIn("unsupported", adapters)
        self.assertIn("offline_audit_record", adapters)
        self.assertEqual(adapters["offline_audit_record"]["credential_policy"], "none")
        self.assertEqual(adapters["offline_audit_record"]["listener_policy"], "none")
        self.assertTrue(adapters["offline_audit_record"]["one_shot"])
        self.assertEqual(adapters["offline_audit_record"]["timeout_behavior"], "fail_closed")
        self.assertIn("execution_record", adapters["offline_audit_record"]["evidence_capture"])

    def test_offline_adapter_lifecycle_is_audited(self):
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
                    reason="authorized adapter sdk lifecycle test",
                    audit_log=str(audit_log),
                    module="relayx_audit_record",
                    scope=load_scope("filesrv01"),
                ),
            )
            audit_row = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(run["result"]["state"], "executed_offline")
        self.assertEqual([row["phase"] for row in run["adapter_lifecycle"]], ["prepare", "execute", "cleanup"])
        self.assertTrue(all(not row["network_action"] for row in run["adapter_lifecycle"]))
        self.assertEqual(audit_row["adapter_lifecycle"][1]["state"], "executed")
        self.assertEqual(run["adapter_sdk"]["credential_policy"], "none")
        self.assertTrue(run["execution_contract"]["one_shot"])
        self.assertEqual(run["execution_contract"]["timeout_behavior"], "fail_closed")
        self.assertIn("jsonl_audit_entry", run["execution_contract"]["evidence_capture"])

    def test_supported_manifest_without_registered_adapter_is_blocked(self):
        result = _result_with_smb_ready_path()
        registry = {
            "lab_live": ExecutionModuleSpec(
                key="lab_live",
                label="Lab live adapter contract",
                supported=True,
                reason="Lab-only adapter contract for SDK testing.",
                adapter="lab_only_live",
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
                    reason="authorized adapter registry negative test",
                    audit_log=str(Path(tmp) / "audit.jsonl"),
                    module="lab_live",
                    module_registry=registry,
                    scope=load_scope("filesrv01"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(row["key"] == "adapter_registered" and row["state"] == "fail" for row in run["guardrails"]))
        self.assertFalse(run["adapter_lifecycle"])

    def test_unsafe_credential_policy_is_blocked_even_with_registered_adapter(self):
        result = _result_with_smb_ready_path()
        registry = {
            "unsafe_policy": ExecutionModuleSpec(
                key="unsafe_policy",
                label="Unsafe credential policy adapter",
                supported=True,
                reason="Deliberately unsafe SDK policy test.",
                adapter="offline_audit_record",
                credential_policy="capture_allowed",
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
                    reason="authorized credential policy negative test",
                    audit_log=str(Path(tmp) / "audit.jsonl"),
                    module="unsafe_policy",
                    module_registry=registry,
                    scope=load_scope("filesrv01"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(row["key"] == "credential_policy" and row["state"] == "fail" for row in run["guardrails"]))

    def test_supported_module_cannot_use_unsupported_adapter_boundary(self):
        result = _result_with_smb_ready_path()
        registry = {
            "inconsistent": ExecutionModuleSpec(
                key="inconsistent",
                label="Inconsistent adapter support",
                supported=True,
                reason="Deliberately inconsistent SDK policy test.",
                adapter="unsupported",
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
                    reason="authorized support consistency negative test",
                    audit_log=str(Path(tmp) / "audit.jsonl"),
                    module="inconsistent",
                    module_registry=registry,
                    scope=load_scope("filesrv01"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertTrue(any(row["key"] == "adapter_support_consistency" and row["state"] == "fail" for row in run["guardrails"]))

    def test_module_plan_includes_adapter_sdk_contract(self):
        result = _result_with_smb_ready_path()
        plan = build_module_plan(
            result,
            result.paths[0].id,
            load_module_registry(),
            module_key="relayx_audit_record",
        )
        contract = plan["modules"][0]["adapter_sdk"]

        self.assertTrue(contract["registered"])
        self.assertTrue(contract["credential_policy_safe"])
        self.assertTrue(contract["listener_policy_safe"])
        self.assertTrue(contract["support_consistent"])
        self.assertEqual(contract["adapter"], "offline_audit_record")


def _result_with_smb_ready_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_smb_relayable_finding()]
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
        fixes=["Require SMB signing on this server."],
    )


if __name__ == "__main__":
    unittest.main()
