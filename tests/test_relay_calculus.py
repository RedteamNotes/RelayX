import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.path import build_paths
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
from relayx.outputs import render_calculus, render_controls, render_plan_json


class RelayCalculusTests(unittest.TestCase):
    def test_adcs_path_gets_rule_decision_and_controls(self):
        paths = build_paths(
            [_adcs_finding()],
            sources=[
                SourceAsset(
                    host="ws01",
                    capabilities={"webclient": True},
                    noise_limit=NoiseLevel.MEDIUM,
                )
            ],
            max_noise=NoiseLevel.MEDIUM,
        )

        evidence = {item.key: item for item in paths[0].evidence}

        self.assertEqual(evidence["relayx_target_family"].value, "adcs_web_enrollment")
        self.assertEqual(evidence["relayx_rule_id"].value, "RX-ADCS-HTTP:webclient")
        self.assertEqual(evidence["relayx_decision"].value, "candidate_needs_validation")
        self.assertIn("http_epa", evidence["relayx_controls"].value)
        self.assertIn("adcs_hardening", evidence["relayx_controls"].value)
        self.assertIn("webclient_hardening", evidence["relayx_controls"].value)

    def test_hardening_signal_moves_path_to_calibration_decision(self):
        paths = build_paths(
            [_ldaps_finding("possible_cbt_enforcement")],
            sources=[SourceAsset(host="ws01", capabilities={"webclient": True})],
        )

        path = paths[0]
        evidence = {item.key: item for item in path.evidence}
        gates = evidence["relayx_hardening_gates"].value

        self.assertEqual(evidence["relayx_decision"].value, "candidate_needs_calibration")
        self.assertTrue(any(gate["state"] == "uncertain" for gate in gates))
        self.assertTrue(any("hardening-related signal" in blocker for blocker in path.blockers))

    def test_smb_signing_gate_blocks_path(self):
        paths = build_paths([_smb_blocked_finding()])
        path = paths[0]
        evidence = {item.key: item for item in path.evidence}

        self.assertEqual(path.status, Status.BLOCKED)
        self.assertEqual(evidence["relayx_decision"].value, "blocked")
        self.assertTrue(any(gate["key"] == "smb_signing" for gate in evidence["relayx_hardening_gates"].value))

    def test_plan_json_contains_dry_run_guardrails(self):
        result = ScanResult.new(target_count=1, source_count=1)
        result.sources = [SourceAsset(host="ws01", capabilities={"webclient": True})]
        result.findings = [_adcs_finding()]
        result.paths = build_paths(result.findings, sources=result.sources)

        plan = json.loads(render_plan_json(result, result.paths[0].id))

        self.assertFalse(plan["execution"]["supported"])
        self.assertEqual(plan["rule_id"], "RX-ADCS-HTTP:webclient")
        self.assertEqual(plan["source_capability"], "webclient")
        self.assertTrue(plan["expected_telemetry"])
        self.assertTrue(plan["rollback"])

    def test_calculus_and_controls_renderers(self):
        result = ScanResult.new(target_count=1, source_count=1)
        result.sources = [SourceAsset(host="ws01", capabilities={"webclient": True})]
        result.findings = [_adcs_finding()]
        result.paths = build_paths(result.findings, sources=result.sources)

        calculus = render_calculus(result)
        controls = render_controls(result)

        self.assertIn("RX-ADCS-HTTP:webclient", calculus)
        self.assertIn("decision=candidate_needs_validation", calculus)
        self.assertIn("HTTP Extended Protection for Authentication", controls)

    def test_cli_plan_json_writes_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            plan_file = root / "plan.json"
            result = ScanResult.new(target_count=1, source_count=1)
            result.sources = [SourceAsset(host="ws01", capabilities={"webclient": True})]
            result.findings = [_adcs_finding()]
            result.paths = build_paths(result.findings, sources=result.sources)
            write_result(result, str(result_file))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "plan",
                        str(result_file),
                        result.paths[0].id,
                        "--format",
                        "json",
                        "--out",
                        str(plan_file),
                    ]
                )

            plan = json.loads(plan_file.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertEqual(plan["rule_id"], "RX-ADCS-HTTP:webclient")
        self.assertFalse(plan["execution"]["supported"])


def _adcs_finding() -> Finding:
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
            Evidence(EvidenceType.OBSERVED, "ntlm_type2_challenge", True, Confidence.HIGH),
            Evidence(EvidenceType.INFERRED, "relayx_response_classification", "not_performed", Confidence.LOW),
        ],
        fixes=["Enable EPA on AD CS Web Enrollment."],
    )


def _ldaps_finding(classification: str) -> Finding:
    return Finding(
        host="dc01",
        port=636,
        protocol="ldaps",
        name="ldaps_channel_binding",
        status=Status.CANDIDATE,
        confidence=Confidence.MEDIUM,
        impact=Impact.MEDIUM,
        summary="LDAPS SASL NTLM Type2 challenge was observed.",
        evidence=[
            Evidence(EvidenceType.OBSERVED, "ldap_sasl_ntlm_type2_challenge", True, Confidence.HIGH),
            Evidence(EvidenceType.OBSERVED, "tls_certificate_sha256", "abc123", Confidence.MEDIUM),
            Evidence(EvidenceType.OBSERVED, "relayx_response_classification", classification, Confidence.MEDIUM),
        ],
        fixes=["Require LDAP channel binding."],
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
        evidence=[
            Evidence(EvidenceType.OBSERVED, "smb_signing_required", True, Confidence.HIGH),
        ],
        blockers=["SMB signing required"],
    )


if __name__ == "__main__":
    unittest.main()
