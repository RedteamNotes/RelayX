import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.enterprise import write_enterprise_bundle
from relayx.engine.path import build_paths
from relayx.engine.quality import run_quality_gate
from relayx.engine.schema import validate_schema_object, validate_schema_path
from relayx.io import write_result
from relayx.models import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Impact,
    ScanResult,
    SourceAsset,
    Status,
)


class EnterpriseCITests(unittest.TestCase):
    def test_enterprise_bundle_writes_valid_manifest_and_artifacts(self):
        result = _result_with_source()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_enterprise_bundle(
                result,
                tmp,
                formats=["opengraph", "jsonl", "csv"],
                include_routes=True,
            )
            root = Path(tmp)
            manifest_path = root / "manifest.json"

            self.assertTrue(manifest_path.exists())
            self.assertTrue(manifest["validation"]["valid"])
            self.assertEqual(manifest["artifact_count"], len(manifest["artifacts"]))
            self.assertTrue((root / "relayx-result.json").exists())
            self.assertTrue((root / "relayx-opengraph.json").exists())
            self.assertTrue((root / "relayx-events.jsonl").exists())
            self.assertTrue((root / "relayx.csv").exists())
            self.assertTrue((root / "relayx-routes.json").exists())
            for artifact in manifest["artifacts"]:
                self.assertEqual(len(artifact["sha256"]), 64)

            manifest_report = validate_schema_path(str(manifest_path), "bundle-manifest")
            self.assertTrue(manifest_report.valid, manifest_report.as_dict())
            self.assertTrue(validate_schema_path(str(root / "relayx-opengraph.json"), "opengraph").valid)
            self.assertTrue(validate_schema_path(str(root / "relayx-events.jsonl"), "jsonl").valid)
            self.assertTrue(validate_schema_path(str(root / "relayx.csv"), "csv").valid)
            self.assertTrue(validate_schema_path(str(root / "relayx-routes.json"), "route-report").valid)

    def test_quality_gate_report_satisfies_schema(self):
        report = run_quality_gate(".")
        schema_report = validate_schema_object(report, "quality-gate")

        self.assertEqual(report["status"], "pass", report)
        self.assertTrue(schema_report.valid, schema_report.as_dict())
        self.assertEqual(report["contract"]["exit_code_on_failure"], 2)
        self.assertIn("quality_gate.contract", report["contract"]["required_checks"])
        self.assertIn("fixtures.lab_determinism", report["contract"]["required_checks"])
        self.assertTrue(report["contract"]["release_automation_ready"])
        self.assertIn("ci.workflows", {check["name"] for check in report["checks"]})
        self.assertIn("cli.help_registry", {check["name"] for check in report["checks"]})
        self.assertIn("cli.short_options", {check["name"] for check in report["checks"]})
        self.assertIn("cli.short_options.docs", {check["name"] for check in report["checks"]})
        self.assertIn("cli.console_contract", {check["name"] for check in report["checks"]})
        self.assertIn("cli.completion_contract", {check["name"] for check in report["checks"]})
        self.assertIn("docs.cli_sync", {check["name"] for check in report["checks"]})
        self.assertIn("fixtures.evidence_report", {check["name"] for check in report["checks"]})
        self.assertIn("fixtures.lab_determinism", {check["name"] for check in report["checks"]})
        self.assertIn("fixtures.lab_provenance", {check["name"] for check in report["checks"]})
        self.assertIn("docs.integration_tests", {check["name"] for check in report["checks"]})
        self.assertIn("version.consistency", {check["name"] for check in report["checks"]})

    def test_cli_bundle_and_quality_gate(self):
        result = _result_with_source()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "result.json"
            bundle_dir = root / "bundle"
            bundle_summary = root / "bundle-summary.json"
            gate_report = root / "quality-gate.json"
            write_result(result, str(result_path))

            with contextlib.redirect_stdout(io.StringIO()):
                rc_bundle = main(
                    [
                        "-q",
                        "bundle",
                        "-r",
                        str(result_path),
                        "-d",
                        str(bundle_dir),
                        "-F",
                        "opengraph,jsonl,csv",
                        "-f",
                        "json",
                        "-o",
                        str(bundle_summary),
                    ]
                )
                rc_gate = main(
                    [
                        "-q",
                        "quality-gate",
                        "-C",
                        ".",
                        "-f",
                        "json",
                        "-o",
                        str(gate_report),
                    ]
                )

            self.assertEqual(rc_bundle, 0)
            self.assertEqual(rc_gate, 0)
            self.assertTrue((bundle_dir / "manifest.json").exists())
            self.assertEqual(json.loads(gate_report.read_text(encoding="utf-8"))["status"], "pass")


def _result_with_source() -> ScanResult:
    result = ScanResult.new(target_count=1, source_count=1)
    result.sources = [
        SourceAsset(
            host="jump01.redteamnotes.com",
            capabilities={"webclient": True},
            subnets=["10.10.0.0/16"],
            route_hops=[
                {
                    "id": "ligolo-1",
                    "kind": "ligolo",
                    "subnets": ["10.10.0.0/16"],
                    "risk_level": "medium",
                }
            ],
        )
    ]
    result.findings = [_http_candidate()]
    result.paths = build_paths(result.findings, sources=result.sources)
    result.finish()
    return result


def _http_candidate() -> Finding:
    return Finding(
        host="ca01.redteamnotes.com",
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
        fixes=["Enable EPA on AD CS Web Enrollment."],
    )


if __name__ == "__main__":
    unittest.main()
