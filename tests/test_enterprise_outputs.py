import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx.cli import main
from relayx.engine.enterprise import (
    diff_results,
    export_csv,
    export_jsonl,
    export_opengraph,
    simulate_fixes,
)
from relayx.engine.path import build_paths
from relayx.engine.profiles import list_profiles, load_profile
from relayx.io import write_result
from relayx.models import (
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    Impact,
    ScanResult,
    Status,
)
from relayx.outputs import render_html


class EnterpriseOutputTests(unittest.TestCase):
    def test_opengraph_export_contains_custom_nodes_and_edges(self):
        result = _result_with_smb_and_http()
        graph = export_opengraph(result)
        kinds = {kind for node in graph["graph"]["nodes"] for kind in node["kinds"]}
        edge_kinds = {edge["kind"] for edge in graph["graph"]["edges"]}

        self.assertEqual(graph["metadata"]["format"], "bloodhound-opengraph")
        self.assertEqual(graph["metadata"]["field_contract_version"], 1)
        self.assertIn("RelayXPathMitigatedBy", graph["mapping"]["edge_kinds"])
        self.assertIn("RelayXPath", kinds)
        self.assertIn("RelayXControl", kinds)
        self.assertIn("RelayXTargetService", kinds)
        self.assertIn("RelayXCandidateRelay", edge_kinds)
        self.assertTrue(all("id" in edge for edge in graph["graph"]["edges"]))

    def test_jsonl_export_is_siem_friendly(self):
        result = _result_with_smb_and_http()
        rows = [json.loads(line) for line in export_jsonl(result).splitlines()]
        event_types = {row["event_type"] for row in rows}

        self.assertIn("relayx.scan", event_types)
        self.assertIn("relayx.finding", event_types)
        self.assertIn("relayx.path", event_types)
        self.assertIn("relayx.control", event_types)
        path_row = next(row for row in rows if row["event_type"] == "relayx.path" and row["target"] == "filesrv01")
        self.assertEqual(path_row["field_contract_version"], 1)
        self.assertIn("smb_signing", path_row["control_keys"])
        self.assertIn("remaining_uncertainty", path_row)

    def test_csv_export_contains_findings_and_paths(self):
        result = _result_with_smb_and_http()
        csv_text = export_csv(result)

        self.assertIn("record_type,id,host,port,protocol", csv_text)
        self.assertIn("control_keys,control_labels,route_state", csv_text)
        self.assertIn("field_contract_version", csv_text)
        self.assertIn("finding,,filesrv01,445,smb", csv_text)
        self.assertIn(",filesrv01,,,candidate", csv_text)

    def test_html_report_includes_enterprise_filters(self):
        result = _result_with_smb_and_http()
        html = render_html(result)

        self.assertIn("statusFilter", html)
        self.assertIn("severityFilter", html)
        self.assertIn("sourceCapabilityFilter", html)
        self.assertIn("targetFamilyFilter", html)
        self.assertIn("controlFilter", html)
        self.assertIn('data-target-family="smb_unsigned"', html)

    def test_diff_reports_added_and_changed_paths(self):
        old = _result_with_smb_only()
        new = _result_with_smb_and_http()
        for path in new.paths:
            if path.target == "filesrv01":
                path.score += 7
        diff = diff_results(old, new)

        self.assertEqual(diff["summary"]["added_paths"], 1)
        self.assertEqual(diff["summary"]["changed_paths"], 1)
        self.assertEqual(diff["summary"]["exposure_trend"], "regressed")
        self.assertGreaterEqual(diff["summary"]["remediation_regressions"], 1)
        self.assertTrue(diff["control_trends"])
        self.assertTrue(diff["added_paths"][0]["target"].startswith("ca"))

    def test_simulate_fixes_accepts_fix_text_and_control(self):
        result = _result_with_smb_and_http()

        by_fix = simulate_fixes(result, fixes=["Require SMB signing"], top=5)
        by_control = simulate_fixes(result, fixes=["control:smb_signing"], top=5)

        self.assertGreaterEqual(by_fix["simulations"][0]["paths_reduced"], 1)
        self.assertGreaterEqual(by_control["simulations"][0]["paths_reduced"], 1)
        self.assertIn("control_dependencies", by_control["simulations"][0])
        self.assertIn("residual_exposure", by_control["simulations"][0])
        self.assertIn("remaining_control_keys", by_control["simulations"][0]["residual_exposure"])
        affected = [
            path.id
            for path in result.paths
            if path.target == "filesrv01"
        ]
        self.assertEqual(by_control["simulations"][0]["affected_path_ids"], affected)

    def test_profiles_are_loadable(self):
        profiles = {row["name"] for row in list_profiles()}
        enterprise = load_profile("enterprise")

        self.assertIn("default", profiles)
        self.assertIn("enterprise", profiles)
        self.assertEqual(enterprise["max_noise"], "medium")

    def test_cli_export_diff_simulate_and_profiles(self):
        old = _result_with_smb_only()
        new = _result_with_smb_and_http()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_file = root / "old.json"
            new_file = root / "new.json"
            graph_file = root / "graph.json"
            diff_file = root / "diff.json"
            sim_file = root / "sim.json"
            profiles_file = root / "profiles.json"
            write_result(old, str(old_file))
            write_result(new, str(new_file))

            with contextlib.redirect_stdout(io.StringIO()):
                rc_export = main(["export", "--result", str(new_file), "--format", "opengraph", "--out", str(graph_file)])
                rc_diff = main(["diff", str(old_file), str(new_file), "--format", "json", "--out", str(diff_file)])
                rc_sim = main(["simulate-fixes", str(new_file), "--control", "smb_signing", "--format", "json", "--out", str(sim_file)])
                rc_profiles = main(["profiles", "--format", "json", "--out", str(profiles_file)])

            graph = json.loads(graph_file.read_text(encoding="utf-8"))
            diff = json.loads(diff_file.read_text(encoding="utf-8"))
            simulation = json.loads(sim_file.read_text(encoding="utf-8"))
            profiles = json.loads(profiles_file.read_text(encoding="utf-8"))

        self.assertEqual(rc_export, 0)
        self.assertEqual(rc_diff, 0)
        self.assertEqual(rc_sim, 0)
        self.assertEqual(rc_profiles, 0)
        self.assertIn("graph", graph)
        self.assertEqual(diff["summary"]["added_paths"], 1)
        self.assertGreaterEqual(simulation["simulations"][0]["paths_reduced"], 1)
        self.assertTrue(any(row["name"] == "enterprise" for row in profiles["profiles"]))


def _result_with_smb_only() -> ScanResult:
    result = ScanResult.new(target_count=1)
    result.findings = [_smb_relayable_finding()]
    result.paths = build_paths(result.findings)
    return result


def _result_with_smb_and_http() -> ScanResult:
    result = ScanResult.new(target_count=2)
    result.findings = [_smb_relayable_finding(), _http_candidate()]
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
        fixes=["Enable EPA on AD CS Web Enrollment."],
    )


if __name__ == "__main__":
    unittest.main()
