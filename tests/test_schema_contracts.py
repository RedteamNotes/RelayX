import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.calibration import assess_lab_differentials, assess_lab_provenance, assess_lab_stability, build_signature_corpus, load_corpuses
from relayx.engine.evidence_report import build_evidence_report
from relayx.engine.enterprise import export_csv, export_jsonl, export_opengraph
from relayx.engine.execution import ExecutionRequest, execute_path
from relayx.engine.path import build_paths
from relayx.engine.schema import (
    SCHEMA_VERSION,
    schema_contracts,
    validate_schema_object,
    validate_schema_path,
)
from relayx.engine.scope import load_scope
from relayx.io import write_result
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, NoiseLevel, RelayPath, ScanResult, SourceAsset, Status, to_plain


FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures"


class SchemaContractTests(unittest.TestCase):
    def test_schema_catalog_lists_artifact_contracts(self):
        catalog = schema_contracts()
        kinds = {row["kind"] for row in catalog["kinds"]}

        self.assertEqual(catalog["schema_version"], SCHEMA_VERSION)
        self.assertIn("result", kinds)
        self.assertIn("evidence", kinds)
        self.assertIn("lab-profile", kinds)
        self.assertIn("lab-provenance", kinds)
        self.assertIn("lab-stability", kinds)
        self.assertIn("lab-differential", kinds)
        self.assertIn("evidence-report", kinds)
        self.assertIn("execution-record", kinds)
        self.assertIn("bundle-manifest", kinds)
        self.assertIn("quality-gate", kinds)

    def test_result_object_validates_with_schema_version(self):
        result = _result_with_smb_ready_path()
        report = validate_schema_object(to_plain(result), "result")

        self.assertTrue(report.valid, [issue.as_dict() for issue in report.issues])
        self.assertEqual(report.kind, "result")

    def test_legacy_result_without_schema_version_is_valid_with_warning(self):
        result = to_plain(_result_with_smb_ready_path())
        del result["metadata"]["schema_version"]
        report = validate_schema_object(result, "result")

        self.assertTrue(report.valid)
        self.assertTrue(any(issue.severity == "warning" for issue in report.issues))

    def test_invalid_evidence_reports_path_level_error(self):
        report = validate_schema_object(
            {"type": "observed", "key": "", "confidence": "certain", "value": True},
            "evidence",
        )

        self.assertFalse(report.valid)
        issue_paths = {issue.path for issue in report.issues}
        self.assertIn("$.key", issue_paths)
        self.assertIn("$.confidence", issue_paths)

    def test_lab_corpus_validates(self):
        corpus = build_signature_corpus(
            _result_with_smb_ready_path(),
            label="smb-signing-lab",
            environment="win2022",
            policy_state="smb_signing_not_required",
        )
        report = validate_schema_object(corpus, "lab-corpus")

        self.assertTrue(report.valid, [issue.as_dict() for issue in report.issues])
        self.assertEqual(corpus["metadata"]["schema_version"], SCHEMA_VERSION)

    def test_lab_stability_report_validates(self):
        report = assess_lab_stability(load_corpuses([str(FIXTURE_ROOT / "lab_corpus")]), min_captures=1)
        schema_report = validate_schema_object(report, "lab-stability")

        self.assertTrue(schema_report.valid, [issue.as_dict() for issue in schema_report.issues])
        self.assertEqual(report["confidence_contract"]["evidence_model"], "repeat_capture_stability")

    def test_lab_provenance_report_validates(self):
        report = assess_lab_provenance(load_corpuses([str(FIXTURE_ROOT / "lab_corpus")]))
        schema_report = validate_schema_object(report, "lab-provenance")

        self.assertTrue(schema_report.valid, [issue.as_dict() for issue in schema_report.issues])
        self.assertEqual(report["confidence_contract"]["evidence_model"], "lab_corpus_provenance_review")
        self.assertEqual(report["summary"]["promotion_ready"], 0)

    def test_lab_differential_report_validates(self):
        report = assess_lab_differentials(load_corpuses([str(FIXTURE_ROOT / "lab_corpus")]), min_captures=1)
        schema_report = validate_schema_object(report, "lab-differential")

        self.assertTrue(schema_report.valid, [issue.as_dict() for issue in schema_report.issues])
        self.assertEqual(report["confidence_contract"]["evidence_model"], "lab_response_differential")

    def test_evidence_report_validates(self):
        report = build_evidence_report(_result_with_smb_ready_path())
        schema_report = validate_schema_object(report, "evidence-report")

        self.assertTrue(schema_report.valid, [issue.as_dict() for issue in schema_report.issues])
        self.assertEqual(report["confidence_contract"]["evidence_model"], "result_evidence_completeness")
        self.assertEqual(report["status"], "pass")
        self.assertIn("wire_observation", report["summary"]["source_categories"])
        self.assertIn("control_mapping", report["summary"]["source_categories"])
        self.assertEqual(report["summary"]["taxonomy_generic"], 0)
        self.assertEqual(report["confidence_contract"]["source_taxonomy_version"], 1)
        for record in report["records"]:
            self.assertEqual(record["evidence_count"], len(record["evidence_sources"]))

    def test_evidence_report_fails_candidate_without_evidence(self):
        result = ScanResult.new(target_count=1)
        result.findings = [
            Finding(
                host="web01.redteamnotes.com",
                port=80,
                protocol="http",
                name="http_ntlm_endpoint",
                status=Status.CANDIDATE,
                confidence=Confidence.MEDIUM,
                impact=Impact.MEDIUM,
                summary="Candidate without evidence for contract test.",
            )
        ]
        result.finish()

        report = build_evidence_report(result)
        schema_report = validate_schema_object(report, "evidence-report")

        self.assertTrue(schema_report.valid, [issue.as_dict() for issue in schema_report.issues])
        self.assertEqual(report["status"], "fail")
        self.assertIn("evidence", report["records"][0]["missing_contract_keys"])

    def test_evidence_report_source_taxonomy_classifies_context(self):
        result = _result_with_source_context()
        report = build_evidence_report(result)
        record = report["records"][0]

        self.assertEqual(report["status"], "pass")
        self.assertEqual(record["source_category_counts"]["source_model"], 1)
        self.assertEqual(record["source_category_counts"]["route_model"], 1)
        self.assertEqual(record["source_category_counts"]["control_mapping"], 1)
        self.assertEqual(record["source_category_counts"]["policy_inference"], 3)
        categories = {row["key"]: row["source_category"] for row in record["evidence_sources"]}
        self.assertEqual(categories["source_capability"], "source_model")
        self.assertEqual(categories["route_reachable"], "route_model")
        self.assertEqual(categories["relayx_policy_inference"], "policy_inference")

    def test_source_contract_accepts_route_awareness_fields(self):
        result = ScanResult.new(target_count=1, source_count=1)
        result.sources = [SourceAsset(
            host="ws01",
            capabilities={"webclient": True},
            session="ligolo-ws01",
            segment="workstations",
            subnets=["10.10.0.0/16"],
            route_hops=[
                {
                    "kind": "ligolo",
                    "name": "agent-ws01",
                    "networks": ["10.20.0.0/16"],
                    "requires_listener": False,
                }
            ],
            noise_limit=NoiseLevel.MEDIUM,
        )]
        result.finish()
        report = validate_schema_object(to_plain(result), "result")

        self.assertTrue(report.valid, [issue.as_dict() for issue in report.issues])

    def test_fixture_profiles_and_module_manifests_validate(self):
        profile_report = validate_schema_path(str(FIXTURE_ROOT / "lab_profiles"), "lab-profile")
        corpus_report = validate_schema_path(str(FIXTURE_ROOT / "lab_corpus"), "lab-corpus")
        module_report = validate_schema_path(str(FIXTURE_ROOT / "execution_modules"), "module-manifest")
        opsec_report = validate_schema_path(str(FIXTURE_ROOT / "opsec_policies"), "opsec-policy")

        self.assertTrue(profile_report.valid)
        self.assertTrue(corpus_report.valid)
        self.assertTrue(module_report.valid)
        self.assertTrue(opsec_report.valid)
        self.assertEqual(profile_report.summary["files"], 5)
        self.assertEqual(corpus_report.summary["files"], 5)
        self.assertEqual(module_report.summary["files"], 3)
        self.assertEqual(opsec_report.summary["files"], 1)

    def test_generated_enterprise_exports_validate(self):
        result = _result_with_smb_ready_path()
        graph_report = validate_schema_object(export_opengraph(result), "opengraph")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jsonl_file = root / "events.jsonl"
            csv_file = root / "relayx.csv"
            jsonl_file.write_text(export_jsonl(result), encoding="utf-8")
            csv_file.write_text(export_csv(result), encoding="utf-8")

            jsonl_report = validate_schema_path(str(jsonl_file), "jsonl")
            csv_report = validate_schema_path(str(csv_file), "csv")

        self.assertTrue(graph_report.valid, [issue.as_dict() for issue in graph_report.issues])
        self.assertTrue(jsonl_report.valid, jsonl_report.as_dict())
        self.assertTrue(csv_report.valid, csv_report.as_dict())

    def test_execution_record_validates(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            run = execute_path(
                result,
                ExecutionRequest(
                    path_id=result.paths[0].id,
                    mode="confirmed",
                    confirm=True,
                    operator="redpen",
                    reason="authorized schema contract test",
                    audit_log=str(Path(tmp) / "audit.jsonl"),
                    module="relayx_audit_record",
                    scope=load_scope("filesrv01"),
                ),
            )
        report = validate_schema_object(run, "execution-record")

        self.assertTrue(report.valid, [issue.as_dict() for issue in report.issues])

    def test_cli_schema_list_and_validate_json(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            write_result(result, str(result_file))

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc_list = main(["schema", "list", "--format", "json"])
            catalog = json.loads(stdout.getvalue())

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc_validate = main(["schema", "validate", str(result_file), "--format", "json"])
            validation = json.loads(stdout.getvalue())

        self.assertEqual(rc_list, 0)
        self.assertEqual(rc_validate, 0)
        self.assertIn("result", {row["kind"] for row in catalog["kinds"]})
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["files"][0]["kind"], "result")

    def test_cli_schema_validate_invalid_file_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            invalid_file = Path(tmp) / "bad.json"
            invalid_file.write_text('{"metadata": {}}', encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = main(["schema", "validate", str(invalid_file), "--kind", "result", "--format", "json"])
            validation = json.loads(stdout.getvalue())

        self.assertEqual(rc, 2)
        self.assertFalse(validation["valid"])
        self.assertGreater(validation["summary"]["errors"], 0)

    def test_cli_evidence_report_json_validates(self):
        result = _result_with_smb_ready_path()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_file = root / "result.json"
            report_file = root / "evidence-report.json"
            write_result(result, str(result_file))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["evidence-report", "-r", str(result_file), "-f", "json", "-o", str(report_file)])
            report = json.loads(report_file.read_text(encoding="utf-8"))
            schema_report = validate_schema_object(report, "evidence-report")

        self.assertEqual(rc, 0)
        self.assertTrue(schema_report.valid, [issue.as_dict() for issue in schema_report.issues])
        self.assertEqual(report["summary"]["records"], 2)


def _result_with_smb_ready_path() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_smb_relayable_finding()]
    result.paths = build_paths(result.findings)
    result.finish()
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


def _result_with_source_context() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.paths = [
        RelayPath(
            id="PX-0001",
            source="jump01.redteamnotes.com",
            transport="HTTP/NTLM",
            target="ca01.redteamnotes.com",
            target_service="HTTP/80 /certsrv",
            status=Status.CANDIDATE,
            impact=Impact.HIGH,
            confidence=Confidence.MEDIUM,
            summary="Evidence taxonomy path.",
            evidence=[
                Evidence(EvidenceType.INFERRED, "source_capability", "webclient", Confidence.MEDIUM),
                Evidence(EvidenceType.INFERRED, "route_reachable", True, Confidence.HIGH),
                Evidence(EvidenceType.INFERRED, "relayx_controls", ["http_epa"], Confidence.MEDIUM),
                Evidence(EvidenceType.OBSERVED, "ntlm_type2_challenge", True, Confidence.HIGH),
                Evidence(EvidenceType.INFERRED, "relayx_response_classification", "synthetic_auth_rejected", Confidence.MEDIUM),
                Evidence(EvidenceType.INFERRED, "relayx_policy_inference", "epa_not_proven", Confidence.MEDIUM),
                Evidence(
                    EvidenceType.INFERRED,
                    "relayx_remaining_uncertainty",
                    ["EPA state requires lab calibration."],
                    Confidence.MEDIUM,
                ),
            ],
        )
    ]
    result.finish()
    return result


if __name__ == "__main__":
    unittest.main()
