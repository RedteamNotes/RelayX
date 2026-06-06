import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.execution import ExecutionRequest, execute_path
from relayx.engine.modules import load_module_registry
from relayx.engine.opsec_policy import (
    evaluate_path_opsec,
    evaluate_source_opsec,
    list_opsec_policies,
    load_opsec_policy,
)
from relayx.engine.path import build_paths
from relayx.engine.scope import load_scope
from relayx.engine.source import CAPABILITY_SPECS
from relayx.engine.source_validation import SourceCheckRequest, build_source_plan
from relayx.engine.validation import ValidationRequest, validate_path
from relayx.io import write_result
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, NoiseLevel, ScanResult, SourceAsset, Status


FIXTURE_POLICY = Path(__file__).resolve().parents[1] / "fixtures" / "opsec_policies" / "strict_enterprise.json"


class OpsecPolicyTests(unittest.TestCase):
    def test_builtin_and_fixture_policies_load(self):
        names = {policy["name"] for policy in list_opsec_policies()}
        strict = load_opsec_policy("strict")
        fixture = load_opsec_policy(str(FIXTURE_POLICY))

        self.assertIn("standard", names)
        self.assertIn("lab", names)
        self.assertEqual(strict.max_noise, NoiseLevel.MEDIUM)
        self.assertEqual(fixture.name, "strict_enterprise_fixture")
        self.assertTrue(fixture.require_scope_for_confirmed)

    def test_standard_policy_allows_dry_run_path(self):
        result = _result_with_smb_ready_path()
        report = evaluate_path_opsec(
            result.paths[0],
            operation="validation",
            mode="dry-run",
            max_noise=NoiseLevel.HIGH,
        )

        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["state"], "allowed")

    def test_strict_policy_requires_scope_for_confirmed(self):
        result = _result_with_smb_ready_path()
        report = evaluate_path_opsec(
            result.paths[0],
            policy=load_opsec_policy("strict"),
            operation="validation",
            mode="confirmed",
            max_noise=NoiseLevel.HIGH,
            confirm=True,
            operator="redpen",
            reason="authorized strict policy test",
            audit_log="audit.jsonl",
        )

        self.assertEqual(report["decision"], "fail")
        self.assertTrue(any(row["key"] == "scope_required" and row["state"] == "fail" for row in report["outcomes"]))

    def test_policy_blocks_unapproved_network_action(self):
        result = _result_with_smb_ready_path()
        report = evaluate_path_opsec(
            result.paths[0],
            policy=load_opsec_policy("standard"),
            operation="execution",
            mode="confirmed",
            max_noise=NoiseLevel.HIGH,
            scope=load_scope("filesrv01"),
            confirm=True,
            operator="redpen",
            reason="authorized module boundary test",
            audit_log="audit.jsonl",
            network_action="future_relay_module",
        )

        self.assertEqual(report["decision"], "fail")
        self.assertTrue(any(row["key"] == "network_action" and row["state"] == "fail" for row in report["outcomes"]))

    def test_source_policy_blocks_name_resolution_under_strict_policy(self):
        source = SourceAsset(host="dc01", capabilities={"name_resolution": True}, noise_limit=NoiseLevel.HIGH)
        report = evaluate_source_opsec(
            source,
            policy=load_opsec_policy("strict"),
            operation="source-plan",
            capability="name_resolution",
            requested_noise=CAPABILITY_SPECS["name_resolution"].noise,
            max_noise=NoiseLevel.HIGH,
            scope=load_scope("dc01"),
        )

        self.assertEqual(report["decision"], "fail")
        self.assertTrue(any(row["key"] == "source_capability" for row in report["outcomes"]))

    def test_validate_embeds_policy_and_blocks_strict_confirmed_without_scope(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            run = validate_path(
                result,
                ValidationRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized validation policy test",
                    audit_log=str(Path(tmp) / "audit.jsonl"),
                    opsec_policy=load_opsec_policy("strict"),
                ),
            )

        self.assertEqual(run["result"]["state"], "blocked")
        self.assertEqual(run["opsec_policy"]["decision"], "fail")
        self.assertTrue(any(item["key"] == "opsec_policy:scope_required" for item in run["guardrails"]))

    def test_execution_allows_offline_adapter_when_strict_scope_is_satisfied(self):
        result = _result_with_smb_ready_path()
        result.paths[0].opsec_notes = ["Single target readiness path with reviewed source context."]
        with tempfile.TemporaryDirectory() as tmp:
            audit_log = Path(tmp) / "audit.jsonl"
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized offline execution policy test",
                    audit_log=str(audit_log),
                    module="relayx_audit_record",
                    module_registry=load_module_registry(),
                    scope=load_scope("filesrv01"),
                    opsec_policy=load_opsec_policy("strict"),
                ),
            )

        self.assertEqual(run["opsec_policy"]["decision"], "pass")
        self.assertEqual(run["result"]["state"], "executed_offline")

    def test_source_plan_strict_policy_sets_opsec_blocked_state(self):
        sources = [SourceAsset(host="dc01", capabilities={"name_resolution": True}, noise_limit=NoiseLevel.HIGH)]
        plan = build_source_plan(
            sources,
            "dc01",
            "name_resolution",
            SourceCheckRequest(
                max_noise=NoiseLevel.HIGH,
                scope=load_scope("dc01"),
                opsec_policy=load_opsec_policy("strict"),
            ),
        )

        self.assertEqual(plan["state"], "opsec_blocked")
        self.assertEqual(plan["opsec_policy"]["decision"], "fail")

    def test_cli_opsec_list_show_and_validate_policy(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            policies_file = root / "policies.json"
            strict_file = root / "strict.json"
            validation_file = root / "validation.json"
            write_result(result, str(result_file))

            with contextlib.redirect_stdout(io.StringIO()):
                rc_list = main(["opsec", "list", "--format", "json", "--out", str(policies_file)])
                rc_show = main(["opsec", "show", "--policy", "strict", "--format", "json", "--out", str(strict_file)])
                rc_validate = main(
                    [
                        "validate",
                        "--result",
                        str(result_file),
                        "--path-id",
                        result.paths[0].id,
                        "--mode",
                        "confirmed",
                        "--confirm",
                        "--operator",
                        "redpen",
                        "--reason",
                        "authorized strict CLI policy test",
                        "--audit-log",
                        str(root / "audit.jsonl"),
                        "--opsec-policy",
                        "strict",
                        "--format",
                        "json",
                        "--out",
                        str(validation_file),
                    ]
                )
            policies = json.loads(policies_file.read_text(encoding="utf-8"))
            strict = json.loads(strict_file.read_text(encoding="utf-8"))
            validation = json.loads(validation_file.read_text(encoding="utf-8"))

        self.assertEqual(rc_list, 0)
        self.assertEqual(rc_show, 0)
        self.assertEqual(rc_validate, 0)
        self.assertTrue(any(policy["name"] == "strict" for policy in policies["policies"]))
        self.assertEqual(strict["name"], "strict")
        self.assertEqual(validation["opsec_policy"]["decision"], "fail")


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
        fixes=["Require SMB signing."],
    )


if __name__ == "__main__":
    unittest.main()
