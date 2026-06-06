import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from relayx import __version__
from relayx.cli import main
from relayx.engine.calibration import (
    assess_lab_differentials,
    assess_lab_provenance,
    assess_lab_stability,
    build_signature_corpus,
    calibrate_result,
    compare_baseline,
    corpus_to_profile,
    extract_signature,
    load_corpuses,
    load_profiles,
    render_generated_profile,
    render_baseline_comparison,
    render_calibration,
    render_corpus_index,
    render_lab_differentials,
    render_lab_matrix,
    render_lab_provenance,
    render_lab_stability,
    render_lab_verification,
    render_signature_corpus,
    summarize_corpuses,
    standard_lab_matrix,
    verify_lab_corpus,
)
from relayx.io import read_result, write_result
from relayx.models import Confidence, Evidence, EvidenceType, Finding, Impact, ScanResult, Status


PROFILE_DIR = "fixtures/lab_profiles"
CORPUS_DIR = "fixtures/lab_corpus"


class LabCalibrationTests(unittest.TestCase):
    def test_profiles_load_from_default_directory(self):
        profiles = load_profiles(PROFILE_DIR)
        profile_ids = {profile.profile_id for profile in profiles}

        self.assertIn("http_iis_epa", profile_ids)
        self.assertIn("adcs_web_enrollment_epa", profile_ids)
        self.assertIn("ldap_signing", profile_ids)
        self.assertIn("ldaps_cbt", profile_ids)
        self.assertIn("mssql_epa", profile_ids)

    def test_adcs_epa_signal_promotes_calibrated_state(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_adcs_required_finding()]
        profile = load_profiles(f"{PROFILE_DIR}/adcs_web_enrollment_epa.json")

        calibration = calibrate_result(result, profile)
        decision = calibration["decisions"][0]

        self.assertEqual(decision["decision"], "promote_calibrated_state")
        self.assertEqual(decision["calibrated_state"], "adcs_epa_or_cbt_enforcement_signal")
        self.assertIn("Matched lab profile state", decision["reasons"][0])

    def test_synthetic_rejection_is_subdivided_but_not_overpromoted(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_adcs_off_finding()]
        profile = load_profiles(f"{PROFILE_DIR}/adcs_web_enrollment_epa.json")

        calibration = calibrate_result(result, profile)
        decision = calibration["decisions"][0]

        self.assertEqual(decision["decision"], "retain_conservative")
        self.assertEqual(
            decision["calibrated_state"],
            "adcs_web_enrollment_rejects_invalid_credentials_no_epa_signal",
        )
        self.assertIn("does not prove ESC8 exploitability", decision["limitations"][0])

    def test_ldap_signing_stronger_auth_promotes(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_ldap_required_finding()]
        profile = load_profiles(f"{PROFILE_DIR}/ldap_signing.json")

        calibration = calibrate_result(result, profile)
        decision = calibration["decisions"][0]

        self.assertEqual(decision["decision"], "promote_calibrated_state")
        self.assertEqual(decision["calibrated_state"], "ldap_signing_or_confidentiality_required")

    def test_ldaps_cbt_diagnostic_signature(self):
        signature = extract_signature(_ldaps_cbt_required_finding())

        self.assertTrue(signature["ldap_diagnostic_contains_80090346"])
        self.assertIn("channel_binding", signature["response_keywords"])

    def test_mssql_encrypt_on_login_failure_is_retained(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_mssql_encrypt_on_login_failed()]
        profile = load_profiles(f"{PROFILE_DIR}/mssql_epa.json")

        calibration = calibrate_result(result, profile)
        decision = calibration["decisions"][0]

        self.assertEqual(decision["decision"], "retain_conservative")
        self.assertEqual(decision["calibrated_state"], "mssql_invalid_credentials_with_cbt_no_epa_signal")

    def test_compare_baseline_promotes_only_when_differential_signal_exists(self):
        baseline = ScanResult.new(target_count=1)
        baseline.findings = [_adcs_off_finding()]
        candidate = ScanResult.new(target_count=1)
        candidate.findings = [_adcs_required_finding()]
        profile = load_profiles(f"{PROFILE_DIR}/adcs_web_enrollment_epa.json")

        comparison = compare_baseline(baseline, candidate, profile)
        row = comparison["comparisons"][0]

        self.assertTrue(row["promotable"])
        self.assertIn("response_classification", row["differences"])
        self.assertIn("can be promoted", row["conclusion"])
        self.assertEqual(row["evidence_chain"]["promotion_gate"]["decision"], "promote")
        self.assertTrue(row["confidence_contract"]["promotion_gate"]["differential_signal"])
        self.assertIn("baseline_signature_id", row["evidence_chain"])

    def test_compare_baseline_refuses_indistinguishable_captures(self):
        baseline = ScanResult.new(target_count=1)
        baseline.findings = [_adcs_off_finding()]
        candidate = ScanResult.new(target_count=1)
        candidate.findings = [_adcs_off_finding()]
        profile = load_profiles(f"{PROFILE_DIR}/adcs_web_enrollment_epa.json")

        comparison = compare_baseline(baseline, candidate, profile)
        row = comparison["comparisons"][0]

        self.assertFalse(row["promotable"])
        self.assertEqual(row["differences"], {})
        self.assertIn("indistinguishable", row["conclusion"])

    def test_renderers_explain_promotion_and_limits(self):
        result = ScanResult.new(target_count=1)
        result.findings = [_adcs_off_finding()]
        profile = load_profiles(f"{PROFILE_DIR}/adcs_web_enrollment_epa.json")
        calibration = calibrate_result(result, profile)
        comparison = compare_baseline(result, result, profile)

        self.assertIn("retain_conservative", render_calibration(calibration))
        self.assertIn("limit:", render_calibration(calibration))
        self.assertIn("indistinguishable", render_baseline_comparison(comparison))

    def test_cli_calibrate_json_and_annotate_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "result.json"
            report_path = root / "calibration.json"
            annotated_path = root / "annotated.json"
            result = ScanResult.new(target_count=1)
            result.findings = [_adcs_required_finding()]
            write_result(result, str(result_path))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "calibrate",
                        str(result_path),
                        "--profiles",
                        f"{PROFILE_DIR}/adcs_web_enrollment_epa.json",
                        "--format",
                        "json",
                        "--out",
                        str(report_path),
                        "--annotate-out",
                        str(annotated_path),
                    ]
                )

            report = json.loads(report_path.read_text(encoding="utf-8"))
            annotated = read_result(str(annotated_path))

        self.assertEqual(rc, 0)
        self.assertEqual(report["decisions"][0]["decision"], "promote_calibrated_state")
        evidence = {item.key: item for item in annotated.findings[0].evidence}
        self.assertEqual(evidence["relayx_lab_calibration"].value, "adcs_epa_or_cbt_enforcement_signal")

    def test_cli_compare_baseline_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            out_path = root / "comparison.json"
            baseline = ScanResult.new(target_count=1)
            baseline.findings = [_adcs_off_finding()]
            candidate = ScanResult.new(target_count=1)
            candidate.findings = [_adcs_required_finding()]
            write_result(baseline, str(baseline_path))
            write_result(candidate, str(candidate_path))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(
                    [
                        "compare-baseline",
                        "--baseline",
                        str(baseline_path),
                        "--candidate",
                        str(candidate_path),
                        "--profiles",
                        f"{PROFILE_DIR}/adcs_web_enrollment_epa.json",
                        "--format",
                        "json",
                        "--out",
                        str(out_path),
                    ]
                )

            comparison = json.loads(out_path.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        self.assertTrue(comparison["comparisons"][0]["promotable"])

    def test_signature_corpus_generates_reusable_profile(self):
        result = ScanResult.new(target_count=1, active=True)
        result.findings = [_adcs_required_finding()]

        corpus = build_signature_corpus(
            result,
            label="adcs-required",
            environment="win2022-adcs",
            policy_state="epa_required",
            expected_state="adcs_epa_or_cbt_enforcement_signal",
            promotion="promote",
            promotion_reason="Stable EPA diagnostic in lab.",
            remaining_uncertainty=["Only calibrated for this AD CS Web Enrollment fixture."],
        )
        profile_doc = corpus_to_profile(
            [corpus],
            profile_id="adcs_generated",
            target_family="adcs_web_enrollment",
            service="http",
        )

        self.assertEqual(corpus["metadata"]["version"], __version__)
        self.assertTrue(corpus["opsec"]["network_actions_recorded"])
        self.assertEqual(profile_doc["states"][0]["promotion"], "retain")
        self.assertEqual(profile_doc["states"][0]["capture_count"], 1)
        self.assertIn("Only calibrated", profile_doc["states"][0]["limitations"][0])
        self.assertIn("lab provenance review contract", json.dumps(profile_doc))
        self.assertNotIn("host", profile_doc["states"][0]["match"])
        self.assertIn("RelayX Lab Signature Corpus", render_signature_corpus(corpus))
        self.assertIn("RelayX Generated Lab Profile", render_generated_profile(profile_doc))

    def test_fixture_lab_corpus_index_covers_policy_matrix(self):
        corpuses = load_corpuses([CORPUS_DIR])
        index = summarize_corpuses(corpuses)
        families = {row["target_family"]: row for row in index["families"]}
        rendered = render_corpus_index(index)

        self.assertEqual(index["corpus_count"], 5)
        self.assertEqual(index["capture_count"], 14)
        self.assertIn("http_iis_epa", families)
        self.assertIn("adcs_web_enrollment", families)
        self.assertIn("ldap_signing", families)
        self.assertIn("ldaps_cbt", families)
        self.assertIn("mssql_epa", families)
        self.assertEqual(index["promotion_counts"]["promote"], 5)
        self.assertTrue(
            any(
                group["target_family"] == "ldaps_cbt"
                and group["capture_count"] == 2
                and set(group["policy_states"]) == {"ldaps_cbt_never", "ldaps_cbt_when_supported_valid_cbt"}
                for group in index["signature_groups"]
            )
        )
        self.assertIn("RelayX Lab Corpus Index", rendered)

    def test_standard_lab_matrix_covers_expected_policy_states(self):
        matrix = standard_lab_matrix()
        mssql = standard_lab_matrix(target_family="mssql_epa")
        policy_states = {row["policy_state"] for row in matrix["requirements"]}

        self.assertEqual(matrix["summary"]["requirements"], 14)
        self.assertEqual(matrix["summary"]["families"], 5)
        self.assertEqual(mssql["summary"]["requirements"], 4)
        self.assertIn("epa_required", policy_states)
        self.assertIn("adcs_epa_required", policy_states)
        self.assertIn("ldap_signing_required", policy_states)
        self.assertIn("ldaps_cbt_always_bad_bindings", policy_states)
        self.assertIn("mssql_encrypt_req_epa_required", policy_states)
        self.assertIn("RelayX Standard Lab Matrix", render_lab_matrix(matrix))
        self.assertEqual(matrix["confidence_contract"]["version"], 2)

    def test_lab_verify_passes_fixture_corpus_against_standard_matrix(self):
        report = verify_lab_corpus(load_corpuses([CORPUS_DIR]))
        rendered = render_lab_verification(report)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["requirements"], 14)
        self.assertEqual(report["summary"]["passed"], 14)
        self.assertEqual(report["confidence_contract"]["version"], 2)
        self.assertIn("RelayX Lab Corpus Verification", rendered)

    def test_lab_provenance_marks_synthetic_fixtures_not_promotion_ready(self):
        report = assess_lab_provenance(load_corpuses([CORPUS_DIR]))
        rendered = render_lab_provenance(report)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["synthetic_corpuses"], 5)
        self.assertEqual(report["summary"]["promotion_ready"], 0)
        self.assertEqual(report["summary"]["fixture_only_promotion_hints"], 5)
        self.assertEqual(report["confidence_contract"]["evidence_model"], "lab_corpus_provenance_review")
        self.assertTrue(all(row["data_origin"] == "synthetic" for row in report["corpuses"]))
        self.assertIn("Synthetic corpus", json.dumps(report))
        self.assertIn("RelayX Lab Corpus Provenance", rendered)

    def test_lab_provenance_warns_on_unreviewed_operator_promotion(self):
        corpus = _corpus_for_finding(_adcs_required_finding(), label="adcs-required", policy_state="adcs_epa_required")
        report = assess_lab_provenance([corpus], target_family="adcs_web_enrollment")
        block = report["promotion_blocks"][0]

        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["summary"]["unreviewed_promotion_hints"], 1)
        self.assertEqual(report["summary"]["promotion_ready"], 0)
        self.assertIn("Capture review does not explicitly approve", " ".join(block["reasons"]))

    def test_lab_provenance_accepts_operator_reviewed_real_lab_capture(self):
        corpus = _corpus_for_finding(_adcs_required_finding(), label="adcs-required", policy_state="adcs_epa_required")
        corpus["provenance"].update(
            {
                "data_origin": "real_lab",
                "review_status": "operator_reviewed",
                "authorization_ref": "lab-auth-001",
                "operator": "redpen",
                "reviewed_by": "redpen",
                "reviewed_at": "2026-06-05T00:00:00+00:00",
            }
        )
        corpus["endpoint_build"].update(
            {
                "platform": "Windows Server",
                "server_role": "AD CS Web Enrollment with IIS",
                "os_version": "Windows Server 2022",
                "product": "Microsoft AD CS Web Enrollment",
                "product_version": "10.0",
                "policy_matrix": "AD CS EPA required",
                "authentication_provider": "NTLM",
            }
        )
        corpus["captures"][0]["review"].update(
            {
                "status": "operator_reviewed",
                "promotion_decision": "promote",
                "reviewed_by": "redpen",
                "reviewed_at": "2026-06-05T00:00:00+00:00",
            }
        )

        report = assess_lab_provenance([corpus], target_family="adcs_web_enrollment")

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["promotion_ready"], 1)
        self.assertTrue(report["capture_reviews"][0]["promotion_ready"])

    def test_lab_verify_detects_missing_policy_state(self):
        corpus = build_signature_corpus(
            ScanResult.new(target_count=0),
            label="empty",
        )
        report = verify_lab_corpus([corpus], target_family="ldaps_cbt")

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["summary"]["missing"], 3)
        self.assertTrue(any(row["policy_state"] == "ldaps_cbt_always_bad_bindings" for row in report["missing_required"]))

    def test_lab_stability_promotes_only_stable_repeat_captures(self):
        corpuses = [
            _corpus_for_finding(_adcs_required_finding(), label="adcs-required-1", policy_state="adcs_epa_required"),
            _corpus_for_finding(_adcs_required_finding(), label="adcs-required-2", policy_state="adcs_epa_required"),
        ]
        report = assess_lab_stability(
            corpuses,
            target_family="adcs_web_enrollment",
            min_captures=2,
        )
        state = next(row for row in report["policy_states"] if row["policy_state"] == "adcs_epa_required")
        rendered = render_lab_stability(report)

        self.assertEqual(state["status"], "stable")
        self.assertEqual(state["consistency_score"], 1.0)
        self.assertFalse(state["drift_detected"])
        self.assertEqual(state["recommended_profile_promotion"], "promote")
        self.assertEqual(state["promotion_downgrade_reasons"], [])
        self.assertIn("RelayX Lab Capture Stability", rendered)

    def test_lab_stability_detects_drift_and_downgrades_promotion(self):
        corpuses = [
            _corpus_for_finding(_adcs_required_finding(), label="adcs-required-1", policy_state="adcs_epa_required"),
            _corpus_for_finding(_adcs_off_finding(), label="adcs-required-drift", policy_state="adcs_epa_required"),
        ]
        report = assess_lab_stability(
            corpuses,
            target_family="adcs_web_enrollment",
            min_captures=2,
        )
        state = next(row for row in report["policy_states"] if row["policy_state"] == "adcs_epa_required")

        self.assertEqual(state["status"], "drift")
        self.assertTrue(state["drift_detected"])
        self.assertIn("response_classification", state["drift_keys"])
        self.assertEqual(state["recommended_profile_promotion"], "retain")
        self.assertTrue(state["promotion_downgrade_reasons"])

    def test_lab_differentials_find_response_discriminators(self):
        report = assess_lab_differentials(
            load_corpuses([CORPUS_DIR]),
            target_family="http_iis_epa",
            min_captures=1,
        )
        pair = next(row for row in report["pairs"] if row["right_policy_state"] == "epa_required")
        rendered = render_lab_differentials(report)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["summary"]["pairs"], 3)
        self.assertEqual(pair["status"], "differential")
        self.assertEqual(pair["promotion_support"], "strong")
        self.assertTrue(pair["promotable_candidate"])
        self.assertIn("response_classification", pair["discriminator_keys"])
        self.assertIn("RelayX Lab Response Differential", rendered)

    def test_lab_differentials_warn_on_unmatched_pair_filter(self):
        report = assess_lab_differentials(
            load_corpuses([CORPUS_DIR]),
            target_family="http_iis_epa",
            min_captures=1,
            pairs=["epa_off:does_not_exist"],
        )
        rendered = render_lab_differentials(report)

        self.assertEqual(report["status"], "warn")
        self.assertEqual(report["summary"]["pairs"], 0)
        self.assertEqual(report["summary"]["unmatched_pair_filters"], 1)
        self.assertEqual(report["unmatched_pair_filters"], ["epa_off:does_not_exist"])
        self.assertIn("Unmatched", rendered)

    def test_lab_differentials_report_indistinguishable_pairs_without_overpromotion(self):
        report = assess_lab_differentials(
            load_corpuses([CORPUS_DIR]),
            target_family="ldaps_cbt",
            min_captures=1,
        )
        pair = next(row for row in report["pairs"] if row["right_policy_state"] == "ldaps_cbt_when_supported_valid_cbt")

        self.assertEqual(pair["status"], "indistinguishable")
        self.assertEqual(pair["promotion_support"], "none")
        self.assertFalse(pair["promotable_candidate"])
        self.assertEqual(pair["discriminator_keys"], [])

    def test_generated_profile_uses_stability_to_suppress_drifted_promotion(self):
        corpuses = [
            _corpus_for_finding(_adcs_required_finding(), label="adcs-required-1", policy_state="adcs_epa_required"),
            _corpus_for_finding(_adcs_off_finding(), label="adcs-required-drift", policy_state="adcs_epa_required"),
        ]
        profile_doc = corpus_to_profile(
            corpuses,
            profile_id="adcs_generated",
            target_family="adcs_web_enrollment",
            min_captures=2,
        )

        self.assertEqual(profile_doc["source_corpus"]["stability_status"], "fail")
        self.assertTrue(all(state["promotion"] == "retain" for state in profile_doc["states"]))
        self.assertIn("repeat-capture stability is not proven", json.dumps(profile_doc))

    def test_generated_profile_from_fixture_corpus_preserves_source_metadata(self):
        profile_doc = corpus_to_profile(
            load_corpuses([CORPUS_DIR]),
            profile_id="mssql_generated",
            target_family="mssql_epa",
            service="mssql",
        )
        as_text = json.dumps(profile_doc, sort_keys=True)
        states = {state["name"]: state for state in profile_doc["states"]}

        self.assertEqual(profile_doc["source_corpus"]["target_family_capture_count"], 4)
        self.assertIn("mssql_encrypt_req_epa_required", states)
        self.assertEqual(states["mssql_encrypt_req_epa_required"]["promotion"], "retain")
        self.assertTrue(states["mssql_encrypt_req_epa_required"]["source_signature_ids"])
        self.assertNotIn("redpen", as_text)
        self.assertIn("channel binding", as_text)
        self.assertIn("Synthetic fixture captures are not real lab promotion evidence", as_text)

    def test_generated_profile_preserves_promotion_after_provenance_review(self):
        corpus = _corpus_for_finding(_adcs_required_finding(), label="adcs-required", policy_state="adcs_epa_required")
        corpus["provenance"].update(
            {
                "data_origin": "real_lab",
                "review_status": "operator_reviewed",
                "authorization_ref": "lab-auth-001",
                "operator": "redpen",
                "reviewed_by": "redpen",
                "reviewed_at": "2026-06-05T00:00:00+00:00",
            }
        )
        corpus["endpoint_build"].update(
            {
                "platform": "Windows Server",
                "server_role": "AD CS Web Enrollment with IIS",
                "os_version": "Windows Server 2022",
                "product": "Microsoft AD CS Web Enrollment",
                "product_version": "10.0",
                "policy_matrix": "AD CS EPA required",
                "authentication_provider": "NTLM",
            }
        )
        corpus["captures"][0]["review"].update(
            {
                "status": "operator_reviewed",
                "promotion_decision": "promote",
                "reviewed_by": "redpen",
                "reviewed_at": "2026-06-05T00:00:00+00:00",
            }
        )

        profile_doc = corpus_to_profile(
            [corpus],
            profile_id="adcs_reviewed",
            target_family="adcs_web_enrollment",
            min_captures=1,
        )

        self.assertEqual(profile_doc["states"][0]["promotion"], "promote")
        self.assertNotIn("lab provenance review contract", json.dumps(profile_doc))

    def test_generated_profile_min_captures_suppresses_single_capture_promotion(self):
        profile_doc = corpus_to_profile(
            load_corpuses([CORPUS_DIR]),
            profile_id="mssql_generated",
            target_family="mssql_epa",
            min_captures=2,
        )
        states = {state["name"]: state for state in profile_doc["states"]}
        state = states["mssql_encrypt_req_epa_required"]

        self.assertEqual(state["promotion"], "retain")
        self.assertTrue(any("below min_captures=2" in item for item in state["limitations"]))

    def test_cli_lab_corpus_and_profile_json_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "result.json"
            corpus_path = root / "corpus.json"
            profile_path = root / "profile.json"
            result = ScanResult.new(target_count=1, active=True)
            result.findings = [_adcs_required_finding()]
            write_result(result, str(result_path))

            with contextlib.redirect_stdout(io.StringIO()):
                rc_corpus = main(
                    [
                        "lab-corpus",
                        str(result_path),
                        "--label",
                        "adcs-required",
                        "--environment",
                        "win2022-adcs",
                        "--policy-state",
                        "epa_required",
                        "--expected-state",
                        "adcs_epa_or_cbt_enforcement_signal",
                        "--promotion",
                        "promote",
                        "--reason",
                        "Stable EPA diagnostic in lab.",
                        "--format",
                        "json",
                        "--out",
                        str(corpus_path),
                    ]
                )
                rc_profile = main(
                    [
                        "lab-profile",
                        "--corpus",
                        str(corpus_path),
                        "--profile-id",
                        "adcs_generated",
                        "--target-family",
                        "adcs_web_enrollment",
                        "--service",
                        "http",
                        "--format",
                        "json",
                        "--out",
                        str(profile_path),
                    ]
                )
            corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            loaded = load_profiles(str(profile_path))
            calibration = calibrate_result(result, loaded)

        self.assertEqual(rc_corpus, 0)
        self.assertEqual(rc_profile, 0)
        self.assertEqual(corpus["metadata"]["mode"], "lab_signature_corpus")
        self.assertEqual(profile["profile_id"], "adcs_generated")
        self.assertEqual(profile["states"][0]["promotion"], "retain")
        self.assertIn("lab provenance review contract", json.dumps(profile))
        self.assertEqual(calibration["decisions"][0]["decision"], "retain_conservative")

    def test_cli_lab_index_and_profile_from_fixture_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index_path = root / "index.json"
            profile_path = root / "profile.json"

            with contextlib.redirect_stdout(io.StringIO()):
                rc_index = main(
                    [
                        "lab-index",
                        "--corpus",
                        CORPUS_DIR,
                        "--target-family",
                        "mssql_epa",
                        "--format",
                        "json",
                        "--out",
                        str(index_path),
                    ]
                )
                rc_profile = main(
                    [
                        "lab-profile",
                        "--corpus",
                        CORPUS_DIR,
                        "--profile-id",
                        "mssql_generated",
                        "--target-family",
                        "mssql_epa",
                        "--min-captures",
                        "2",
                        "--format",
                        "json",
                        "--out",
                        str(profile_path),
                    ]
                )
            index = json.loads(index_path.read_text(encoding="utf-8"))
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            state = next(row for row in profile["states"] if row["name"] == "mssql_encrypt_req_epa_required")

        self.assertEqual(rc_index, 0)
        self.assertEqual(rc_profile, 0)
        self.assertEqual(index["target_family"], "mssql_epa")
        self.assertEqual(index["capture_count"], 4)
        self.assertEqual(profile["source_corpus"]["min_captures"], 2)
        self.assertEqual(state["promotion"], "retain")

    def test_cli_lab_matrix_and_verify_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            matrix_path = root / "matrix.json"
            verify_path = root / "verify.json"
            provenance_path = root / "provenance.json"
            stability_path = root / "stability.json"
            diff_path = root / "diff.json"

            with contextlib.redirect_stdout(io.StringIO()):
                rc_matrix = main(
                    [
                        "lab-matrix",
                        "--target-family",
                        "mssql_epa",
                        "--format",
                        "json",
                        "--out",
                        str(matrix_path),
                    ]
                )
                rc_verify = main(
                    [
                        "lab-verify",
                        "--corpus",
                        CORPUS_DIR,
                        "--format",
                        "json",
                        "--out",
                        str(verify_path),
                    ]
                )
                rc_provenance = main(
                    [
                        "lab-provenance",
                        "--corpus",
                        CORPUS_DIR,
                        "--format",
                        "json",
                        "--out",
                        str(provenance_path),
                    ]
                )
                rc_stability = main(
                    [
                        "lab-stability",
                        "--corpus",
                        CORPUS_DIR,
                        "--min-captures",
                        "1",
                        "--format",
                        "json",
                        "--out",
                        str(stability_path),
                    ]
                )
                rc_diff = main(
                    [
                        "lab-diff",
                        "--corpus",
                        CORPUS_DIR,
                        "--target-family",
                        "http_iis_epa",
                        "--pair",
                        "epa_off:epa_required",
                        "--min-captures",
                        "1",
                        "--format",
                        "json",
                        "--out",
                        str(diff_path),
                    ]
                )
            matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
            verification = json.loads(verify_path.read_text(encoding="utf-8"))
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            stability = json.loads(stability_path.read_text(encoding="utf-8"))
            diff = json.loads(diff_path.read_text(encoding="utf-8"))

        self.assertEqual(rc_matrix, 0)
        self.assertEqual(rc_verify, 0)
        self.assertEqual(rc_provenance, 0)
        self.assertEqual(rc_stability, 0)
        self.assertEqual(rc_diff, 0)
        self.assertEqual(matrix["target_family"], "mssql_epa")
        self.assertEqual(verification["status"], "pass")
        self.assertEqual(provenance["status"], "pass")
        self.assertEqual(verification["summary"]["passed"], 14)
        self.assertEqual(stability["status"], "pass")
        self.assertEqual(stability["summary"]["stable"], 14)
        self.assertEqual(diff["summary"]["pairs"], 1)
        self.assertTrue(diff["pairs"][0]["promotable_candidate"])

    def test_cli_lab_corpus_text_out_respects_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "result.json"
            corpus_path = root / "corpus.txt"
            result = ScanResult.new(target_count=1)
            result.findings = [_adcs_off_finding()]
            write_result(result, str(result_path))

            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["lab-corpus", str(result_path), "--out", str(corpus_path)])

            text = corpus_path.read_text(encoding="utf-8")

        self.assertEqual(rc, 0)
        self.assertIn("RelayX Lab Signature Corpus", text)
        self.assertFalse(text.lstrip().startswith("{"))

    def test_load_corpuses_accepts_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = ScanResult.new(target_count=1)
            result.findings = [_adcs_off_finding()]
            corpus = build_signature_corpus(result, label="adcs-off")
            (root / "adcs-off.json").write_text(json.dumps(corpus), encoding="utf-8")

            corpuses = load_corpuses([str(root)])

        self.assertEqual(len(corpuses), 1)
        self.assertEqual(corpuses[0]["metadata"]["label"], "adcs-off")

    def test_missing_profile_and_corpus_paths_raise_clear_errors(self):
        with self.assertRaisesRegex(ValueError, "calibration profile path does not exist"):
            load_profiles("/not/a/relayx/profile/path")
        with self.assertRaisesRegex(ValueError, "lab corpus path does not exist"):
            load_corpuses(["/not/a/relayx/corpus/path"])

    def test_cli_reports_missing_calibration_profile_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "result.json"
            result = ScanResult.new(target_count=1)
            result.findings = [_adcs_required_finding()]
            write_result(result, str(result_path))
            stderr = io.StringIO()

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                rc = main(
                    [
                        "calibrate",
                        str(result_path),
                        "--profiles",
                        str(root / "missing-profile.json"),
                    ]
                )

        self.assertEqual(rc, 2)
        self.assertIn("calibration profile path does not exist", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_reports_missing_result_without_traceback(self):
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            rc = main(["calibrate", "/not/a/relayx/result.json"])

        self.assertEqual(rc, 2)
        self.assertIn("RelayX result file does not exist", stderr.getvalue())
        self.assertIn("/not/a/relayx/result.json", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


def _adcs_off_finding() -> Finding:
    return Finding(
        host="ca01",
        port=80,
        protocol="http",
        name="adcs_web_enrollment",
        status=Status.CANDIDATE,
        confidence=Confidence.HIGH,
        impact=Impact.HIGH,
        summary="AD CS endpoint advertises NTLM.",
        evidence=[
            Evidence(EvidenceType.OBSERVED, "http_status", 401, Confidence.HIGH),
            Evidence(
                EvidenceType.OBSERVED,
                "ntlm_authenticate_validation",
                True,
                Confidence.MEDIUM,
                raw={
                    "sent": True,
                    "status_code": 401,
                    "reason": "Unauthorized",
                    "cbt_hash": "",
                },
            ),
            Evidence(
                EvidenceType.INFERRED,
                "relayx_response_classification",
                "synthetic_auth_rejected",
                Confidence.MEDIUM,
            ),
        ],
    )


def _adcs_required_finding() -> Finding:
    return Finding(
        host="ca01",
        port=443,
        protocol="https",
        name="adcs_web_enrollment",
        status=Status.CANDIDATE,
        confidence=Confidence.HIGH,
        impact=Impact.HIGH,
        summary="AD CS endpoint advertises NTLM.",
        evidence=[
            Evidence(EvidenceType.OBSERVED, "http_status", 401, Confidence.HIGH),
            Evidence(EvidenceType.OBSERVED, "tls_certificate_sha256", "abc123", Confidence.MEDIUM),
            Evidence(
                EvidenceType.OBSERVED,
                "ntlm_authenticate_validation",
                True,
                Confidence.MEDIUM,
                raw={
                    "sent": True,
                    "status_code": 401,
                    "reason": "Extended Protection required",
                    "www_authenticate": "NTLM channel binding required",
                    "cbt_hash": "00" * 32,
                },
            ),
            Evidence(
                EvidenceType.INFERRED,
                "relayx_response_classification",
                "possible_epa_cbt_enforcement",
                Confidence.MEDIUM,
            ),
        ],
    )


def _corpus_for_finding(finding: Finding, *, label: str, policy_state: str) -> dict:
    result = ScanResult.new(target_count=1, active=True)
    result.findings = [finding]
    return build_signature_corpus(
        result,
        label=label,
        environment="relayx-lab",
        policy_state=policy_state,
        expected_state="adcs_epa_or_cbt_enforcement_signal",
        promotion="promote",
        promotion_reason="Stable EPA diagnostic in lab.",
    )


def _ldap_required_finding() -> Finding:
    return Finding(
        host="dc01",
        port=389,
        protocol="ldap",
        name="ldap_signing",
        status=Status.CANDIDATE,
        confidence=Confidence.MEDIUM,
        impact=Impact.MEDIUM,
        summary="LDAP bind requires stronger auth.",
        evidence=[
            Evidence(
                EvidenceType.OBSERVED,
                "ldap_ntlm_authenticate_validation",
                True,
                Confidence.MEDIUM,
                raw={
                    "sent": True,
                    "result_code": 8,
                    "diagnostic_message": "strongerAuthRequired",
                },
            ),
            Evidence(
                EvidenceType.INFERRED,
                "relayx_response_classification",
                "stronger_auth_or_confidentiality_required",
                Confidence.MEDIUM,
            ),
        ],
    )


def _ldaps_cbt_required_finding() -> Finding:
    return Finding(
        host="dc01",
        port=636,
        protocol="ldaps",
        name="ldaps_channel_binding",
        status=Status.CANDIDATE,
        confidence=Confidence.MEDIUM,
        impact=Impact.MEDIUM,
        summary="LDAPS CBT diagnostic observed.",
        evidence=[
            Evidence(EvidenceType.OBSERVED, "tls_certificate_sha256", "abc123", Confidence.MEDIUM),
            Evidence(
                EvidenceType.OBSERVED,
                "ldap_ntlm_authenticate_validation",
                True,
                Confidence.MEDIUM,
                raw={
                    "sent": True,
                    "result_code": 49,
                    "diagnostic_message": "AcceptSecurityContext error, data 80090346",
                    "cbt_hash": "00" * 32,
                },
            ),
            Evidence(
                EvidenceType.INFERRED,
                "relayx_response_classification",
                "possible_cbt_enforcement",
                Confidence.MEDIUM,
            ),
        ],
    )


def _mssql_encrypt_on_login_failed() -> Finding:
    return Finding(
        host="sql01",
        port=1433,
        protocol="mssql",
        name="mssql_ntlm_epa",
        status=Status.CANDIDATE,
        confidence=Confidence.HIGH,
        impact=Impact.MEDIUM,
        summary="MSSQL SSPI validation observed.",
        evidence=[
            Evidence(EvidenceType.OBSERVED, "tds_prelogin_encryption", "ENCRYPT_ON", Confidence.MEDIUM),
            Evidence(EvidenceType.OBSERVED, "tds_wrapped_tls", True, Confidence.HIGH),
            Evidence(
                EvidenceType.OBSERVED,
                "mssql_ntlm_authenticate_validation",
                True,
                Confidence.MEDIUM,
                raw={
                    "sent": True,
                    "cbt_hash": "00" * 32,
                    "errors": ["Login failed for user 'redpen'."],
                    "infos": [],
                    "loginack": False,
                },
            ),
            Evidence(
                EvidenceType.INFERRED,
                "relayx_response_classification",
                "synthetic_auth_rejected",
                Confidence.MEDIUM,
            ),
        ],
    )


if __name__ == "__main__":
    unittest.main()
