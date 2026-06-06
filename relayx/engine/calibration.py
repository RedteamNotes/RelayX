from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import Confidence, Evidence, EvidenceType, Finding, ScanResult, to_plain


LAB_MATRIX_VERSION = 2

_RESPONSE_DIFFERENTIAL_KEYS = {
    "response_classification",
    "response_subclassification",
    "policy_inference",
    "oracle_signature",
    "http_auth_status",
    "ldap_result_code",
    "ldap_diagnostic_contains_80090346",
    "mssql_errors",
    "mssql_loginack",
    "tds_prelogin_encryption",
    "tds_wrapped_tls",
    "tls_certificate_observed",
    "cbt_hash_observed",
    "response_keywords",
}

_CONTEXT_ONLY_SIGNATURE_KEYS = {
    "target_family",
    "protocol",
    "finding_name",
    "http_status",
    "auth_validation_observed",
}

_LAB_CORPUS_KINDS = {
    "synthetic_fixture",
    "authorized_lab_capture",
    "external_lab_capture",
}

_LAB_DATA_ORIGINS = {
    "synthetic",
    "operator_supplied",
    "real_lab",
    "external",
}

_LAB_REVIEW_STATUSES = {
    "fixture_only",
    "pending_review",
    "operator_reviewed",
    "promotion_approved",
    "promotion_rejected",
    "not_for_promotion",
}

_LAB_PROMOTION_DECISIONS = {
    "pending",
    "retain",
    "promote",
    "block",
    "reject",
    "not_for_promotion",
}

_PROVENANCE_REQUIRED_KEYS = {
    "corpus_kind",
    "data_origin",
    "capture_source",
    "capture_method",
    "review_status",
}

_ENDPOINT_BUILD_REQUIRED_KEYS = {
    "platform",
    "server_role",
    "os_version",
    "product",
    "product_version",
    "policy_matrix",
}

_DRIFT_BASELINE_REQUIRED_KEYS = {
    "baseline_id",
    "minimum_repeated_captures",
    "stable_required_keys",
    "known_unstable_keys",
}

_STANDARD_LAB_MATRIX: tuple[dict[str, Any], ...] = (
    {
        "id": "HTTP-IIS-EPA-OFF",
        "target_family": "http_iis_epa",
        "service": "http",
        "policy_state": "epa_off",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "http-iis-epa-off",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "http_auth_status", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "Ordinary invalid-credential rejection is useful but does not prove EPA is disabled.",
        "remaining_uncertainty": ["EPA off and EPA accept can be indistinguishable with valid CBT absent a differential baseline."],
    },
    {
        "id": "HTTP-IIS-EPA-ACCEPT",
        "target_family": "http_iis_epa",
        "service": "https",
        "policy_state": "epa_accept_with_cbt",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "http-iis-epa-accept-with-cbt",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "http_auth_status", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "EPA accept with valid CBT may still produce ordinary invalid-credential rejection.",
        "remaining_uncertainty": ["Use a controlled no-CBT or malformed-CBT baseline before promoting enforcement conclusions."],
    },
    {
        "id": "HTTP-IIS-EPA-REQUIRED",
        "target_family": "http_iis_epa",
        "service": "https",
        "policy_state": "epa_required",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "http-iis-epa-required",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "http_auth_status", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "promote_when_epa_or_cbt_marker_is_stable",
        "why": "Explicit EPA/CBT diagnostics or stable response differences can support promotion.",
        "remaining_uncertainty": ["Endpoint modules and provider order can change response wording."],
    },
    {
        "id": "ADCS-EPA-OFF",
        "target_family": "adcs_web_enrollment",
        "service": "http",
        "policy_state": "adcs_epa_off",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "adcs-web-enrollment-epa-off",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "http_auth_status", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "AD CS Web Enrollment invalid-credential rejection does not prove template or ESC8 viability.",
        "remaining_uncertainty": ["Certificate template permissions and account context remain separate from relay exposure."],
    },
    {
        "id": "ADCS-EPA-REQUIRED",
        "target_family": "adcs_web_enrollment",
        "service": "https",
        "policy_state": "adcs_epa_required",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "adcs-web-enrollment-epa-required",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "http_auth_status", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "promote_when_epa_or_cbt_marker_is_stable",
        "why": "AD CS EPA diagnostics are high-value discriminators when they are stable in lab.",
        "remaining_uncertainty": ["Keep AD CS endpoint path, authentication providers, and template context fixed across baselines."],
    },
    {
        "id": "LDAP-SIGNING-NONE",
        "target_family": "ldap_signing",
        "service": "ldap",
        "policy_state": "ldap_signing_none",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "ldap-signing-none",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "ldap_result_code"],
        "promotion_expectation": "retain",
        "why": "invalidCredentials alone does not prove LDAP signing is disabled.",
        "remaining_uncertainty": ["Signing policy should be verified with policy state and differential result codes."],
    },
    {
        "id": "LDAP-SIGNING-REQUIRED",
        "target_family": "ldap_signing",
        "service": "ldap",
        "policy_state": "ldap_signing_required",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "ldap-signing-required",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "ldap_result_code"],
        "promotion_expectation": "promote_when_stronger_auth_signal_is_stable",
        "why": "strongerAuthRequired or confidentiality diagnostics can support a blocking-state promotion.",
        "remaining_uncertainty": ["The same result code can reflect signing, sealing, or confidentiality requirements."],
    },
    {
        "id": "LDAPS-CBT-NEVER",
        "target_family": "ldaps_cbt",
        "service": "ldaps",
        "policy_state": "ldaps_cbt_never",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "ldaps-cbt-never",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "ldap_result_code", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "LDAPS with valid CBT can still fail only because credentials are invalid.",
        "remaining_uncertainty": ["This may match when-supported behavior when valid CBT is supplied."],
    },
    {
        "id": "LDAPS-CBT-WHEN-SUPPORTED",
        "target_family": "ldaps_cbt",
        "service": "ldaps",
        "policy_state": "ldaps_cbt_when_supported_valid_cbt",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "ldaps-cbt-when-supported-valid-cbt",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "ldap_result_code", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "When-supported with valid CBT often remains indistinguishable from never with invalid credentials.",
        "remaining_uncertainty": ["Use malformed-CBT or no-CBT baselines to separate enforcement behavior."],
    },
    {
        "id": "LDAPS-CBT-ALWAYS",
        "target_family": "ldaps_cbt",
        "service": "ldaps",
        "policy_state": "ldaps_cbt_always_bad_bindings",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "ldaps-cbt-always-bad-bindings",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "ldap_result_code", "tls_certificate_observed", "cbt_hash_observed", "ldap_diagnostic_contains_80090346"],
        "promotion_expectation": "promote_when_bad_bindings_signal_is_stable",
        "why": "80090346 or equivalent bad-bindings diagnostics are strong CBT discriminators.",
        "remaining_uncertainty": ["Diagnostic language can vary by server version and localization."],
    },
    {
        "id": "MSSQL-ENCRYPT-OFF",
        "target_family": "mssql_epa",
        "service": "mssql",
        "policy_state": "mssql_encrypt_off_no_auth_validation",
        "required": True,
        "command_mode": "default scan plus authorized auth-validation where lab policy permits",
        "expected_capture_label": "mssql-encrypt-off",
        "required_signature_keys": ["response_classification", "tds_prelogin_encryption", "tds_wrapped_tls", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "Without TLS and authenticate-stage response semantics, EPA remains unproven.",
        "remaining_uncertainty": ["SQL Server encryption negotiation and EPA enforcement are separate policy axes."],
    },
    {
        "id": "MSSQL-ENCRYPT-ON",
        "target_family": "mssql_epa",
        "service": "mssql",
        "policy_state": "mssql_encrypt_on_invalid_credentials_with_cbt",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "mssql-encrypt-on-invalid-credentials-with-cbt",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "tds_prelogin_encryption", "tds_wrapped_tls", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "retain",
        "why": "Login failure with CBT evidence proves challenge flow, not EPA state.",
        "remaining_uncertainty": ["EPA off and EPA accept can be indistinguishable with valid CBT."],
    },
    {
        "id": "MSSQL-ENCRYPT-REQ-EPA",
        "target_family": "mssql_epa",
        "service": "mssql",
        "policy_state": "mssql_encrypt_req_epa_required",
        "required": True,
        "command_mode": "confirmed --reprobe --auth-validation in an authorized lab",
        "expected_capture_label": "mssql-encrypt-req-epa-required",
        "required_signature_keys": ["response_classification", "auth_validation_observed", "tds_prelogin_encryption", "tds_wrapped_tls", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "promote_when_channel_binding_signal_is_stable",
        "why": "Stable channel-binding diagnostics can support MSSQL EPA promotion.",
        "remaining_uncertainty": ["SQL error text varies by driver, language, authentication package, and server version."],
    },
    {
        "id": "MSSQL-ENCRYPT-NOT-SUPPORTED",
        "target_family": "mssql_epa",
        "service": "mssql",
        "policy_state": "mssql_encrypt_not_supported",
        "required": True,
        "command_mode": "default scan",
        "expected_capture_label": "mssql-encrypt-not-supported",
        "required_signature_keys": ["response_classification", "tds_prelogin_encryption", "tds_wrapped_tls", "tls_certificate_observed", "cbt_hash_observed"],
        "promotion_expectation": "block_tls_cbt_claims",
        "why": "If TLS is not supported, CBT evidence cannot be collected for MSSQL EPA inference.",
        "remaining_uncertainty": ["Protocol fallback behavior should be reviewed before inferring policy state."],
    },
)


@dataclass(slots=True)
class CalibrationState:
    name: str
    calibrated_state: str
    confidence: str
    promotion: str
    why: str
    match: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CalibrationProfile:
    profile_id: str
    target_family: str
    service: str
    description: str
    discriminators: list[str]
    states: list[CalibrationState]


@dataclass(slots=True)
class CalibrationDecision:
    finding_ref: str
    host: str
    protocol: str
    port: int
    target_family: str
    profile_id: str
    observed_classification: str
    observed_signature: dict[str, Any]
    calibrated_state: str
    decision: str
    confidence: str
    reasons: list[str]
    limitations: list[str]
    matched_state: str = ""
    confidence_contract: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_ref": self.finding_ref,
            "host": self.host,
            "protocol": self.protocol,
            "port": self.port,
            "target_family": self.target_family,
            "profile_id": self.profile_id,
            "observed_classification": self.observed_classification,
            "observed_signature": self.observed_signature,
            "calibrated_state": self.calibrated_state,
            "decision": self.decision,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "limitations": self.limitations,
            "matched_state": self.matched_state,
            "confidence_contract": self.confidence_contract,
        }


@dataclass(slots=True)
class BaselineComparison:
    profile_id: str
    baseline_ref: str
    candidate_ref: str
    target_family: str
    differences: dict[str, dict[str, Any]]
    conclusion: str
    promotable: bool
    reasons: list[str]
    limitations: list[str]
    evidence_chain: dict[str, Any] = field(default_factory=dict)
    confidence_contract: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "baseline_ref": self.baseline_ref,
            "candidate_ref": self.candidate_ref,
            "target_family": self.target_family,
            "differences": self.differences,
            "conclusion": self.conclusion,
            "promotable": self.promotable,
            "reasons": self.reasons,
            "limitations": self.limitations,
            "evidence_chain": self.evidence_chain,
            "confidence_contract": self.confidence_contract,
        }


def load_profiles(path: str | None) -> list[CalibrationProfile]:
    if not path:
        return load_profiles(str(default_profile_dir()))
    root = Path(path)
    if not root.exists():
        raise ValueError(f"calibration profile path does not exist: {path}")
    if root.is_dir():
        return [
            load_profile_file(item)
            for item in sorted(root.glob("*.json"))
            if item.is_file()
        ]
    return [load_profile_file(root)]


def default_profile_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "fixtures" / "lab_profiles"


def load_profile_file(path: Path) -> CalibrationProfile:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"calibration profile {path} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"calibration profile {path} must contain a JSON object")
    for key in ("profile_id", "target_family"):
        if not str(data.get(key, "")).strip():
            raise ValueError(f"calibration profile {path} is missing required field {key!r}")
    state_rows = data.get("states", [])
    if not isinstance(state_rows, list):
        raise ValueError(f"calibration profile {path} field 'states' must be a list")
    states: list[CalibrationState] = []
    for index, state in enumerate(state_rows, start=1):
        if not isinstance(state, dict):
            raise ValueError(f"calibration profile {path} state {index} must be an object")
        for key in ("name", "calibrated_state"):
            if not str(state.get(key, "")).strip():
                raise ValueError(f"calibration profile {path} state {index} is missing required field {key!r}")
        match = state.get("match", {})
        if not isinstance(match, dict):
            raise ValueError(f"calibration profile {path} state {index} field 'match' must be an object")
        states.append(
            CalibrationState(
                name=str(state["name"]),
                calibrated_state=str(state["calibrated_state"]),
                confidence=str(state.get("confidence", "medium")),
                promotion=str(state.get("promotion", "retain")),
                why=str(state.get("why", "")),
                match=dict(match),
                limitations=list(state.get("limitations", [])),
            )
        )
    return CalibrationProfile(
        profile_id=str(data["profile_id"]),
        target_family=str(data["target_family"]),
        service=str(data.get("service", "")),
        description=str(data.get("description", "")),
        discriminators=list(data.get("discriminators", [])),
        states=states,
    )


def calibrate_result(result: ScanResult, profiles: list[CalibrationProfile]) -> dict[str, Any]:
    decisions: list[CalibrationDecision] = []
    by_family = {profile.target_family: profile for profile in profiles}
    for index, finding in enumerate(result.findings, start=1):
        family = target_family_for_finding(finding)
        profile = by_family.get(family)
        if not profile:
            continue
        decisions.append(calibrate_finding(finding, profile, finding_ref=f"F-{index:04d}"))
    summary = _calibration_summary(decisions)
    return {
        "metadata": {
            "tool": "RelayX",
            "mode": "lab_calibration",
            "profiles": [profile.profile_id for profile in profiles],
            "decisions": len(decisions),
        },
        "summary": summary,
        "decisions": [decision.as_dict() for decision in decisions],
    }


def calibrate_finding(
    finding: Finding,
    profile: CalibrationProfile,
    finding_ref: str = "",
) -> CalibrationDecision:
    signature = extract_signature(finding)
    observed = str(signature.get("response_classification") or "not_available")
    matches = [
        state
        for state in profile.states
        if _state_matches(signature, state.match)
    ]
    if not matches:
        return CalibrationDecision(
            finding_ref=finding_ref,
            host=finding.host,
            protocol=finding.protocol,
            port=finding.port,
            target_family=profile.target_family,
            profile_id=profile.profile_id,
            observed_classification=observed,
            observed_signature=signature,
            calibrated_state="uncalibrated",
            decision="retain_conservative",
            confidence="low",
            reasons=[
                "Observed response signature did not match any calibrated lab profile state.",
                "RelayX will retain the conservative classifier output.",
            ],
            limitations=[
                "Add a lab profile state for this exact response pattern before promoting the finding."
            ],
            confidence_contract=_confidence_contract(
                signature,
                profile=profile,
                confidence="low",
                decision="retain_conservative",
                matched_state="",
                limitations=[
                    "Add a lab profile state for this exact response pattern before promoting the finding."
                ],
                promotion_gate={
                    "profile_matched": False,
                    "single_state_match": False,
                    "promotable_state": False,
                    "decision": "retain_conservative",
                },
            ),
        )
    if len(matches) > 1:
        names = ", ".join(state.name for state in matches)
        return CalibrationDecision(
            finding_ref=finding_ref,
            host=finding.host,
            protocol=finding.protocol,
            port=finding.port,
            target_family=profile.target_family,
            profile_id=profile.profile_id,
            observed_classification=observed,
            observed_signature=signature,
            calibrated_state="ambiguous",
            decision="retain_conservative",
            confidence="low",
            reasons=[
                f"Observed response signature matched multiple lab states: {names}.",
                "The profile needs stronger discriminators before RelayX can promote this result.",
            ],
            limitations=_merge_limitations(matches),
            confidence_contract=_confidence_contract(
                signature,
                profile=profile,
                confidence="low",
                decision="retain_conservative",
                matched_state="ambiguous",
                limitations=_merge_limitations(matches),
                promotion_gate={
                    "profile_matched": True,
                    "single_state_match": False,
                    "promotable_state": False,
                    "decision": "retain_conservative",
                },
            ),
        )
    state = matches[0]
    decision = _promotion_decision(state)
    reasons = [
        f"Matched lab profile state {state.name}.",
        state.why or "Profile did not include a detailed rationale.",
    ]
    return CalibrationDecision(
        finding_ref=finding_ref,
        host=finding.host,
        protocol=finding.protocol,
        port=finding.port,
        target_family=profile.target_family,
        profile_id=profile.profile_id,
        observed_classification=observed,
        observed_signature=signature,
        calibrated_state=state.calibrated_state,
        decision=decision,
        confidence=state.confidence,
        reasons=reasons,
        limitations=state.limitations,
        matched_state=state.name,
        confidence_contract=_confidence_contract(
            signature,
            profile=profile,
            confidence=state.confidence,
            decision=decision,
            matched_state=state.name,
            limitations=state.limitations,
            promotion_gate={
                "profile_matched": True,
                "single_state_match": True,
                "promotable_state": decision.startswith("promote_"),
                "decision": decision,
            },
        ),
    )


def compare_baseline(
    baseline: ScanResult,
    candidate: ScanResult,
    profiles: list[CalibrationProfile],
) -> dict[str, Any]:
    comparisons: list[BaselineComparison] = []
    for profile in profiles:
        base_finding = _first_finding_for_family(baseline, profile.target_family)
        cand_finding = _first_finding_for_family(candidate, profile.target_family)
        if not base_finding or not cand_finding:
            continue
        comparisons.append(
            compare_findings(
                base_finding,
                cand_finding,
                profile,
                baseline_ref=f"{base_finding.host}:{base_finding.port}/{base_finding.protocol}",
                candidate_ref=f"{cand_finding.host}:{cand_finding.port}/{cand_finding.protocol}",
            )
        )
    return {
        "metadata": {
            "tool": "RelayX",
            "mode": "baseline_comparison",
            "profiles": [profile.profile_id for profile in profiles],
            "comparisons": len(comparisons),
        },
        "comparisons": [comparison.as_dict() for comparison in comparisons],
    }


def build_signature_corpus(
    result: ScanResult,
    *,
    label: str = "",
    environment: str = "",
    policy_state: str = "",
    expected_classification: str = "",
    expected_state: str = "",
    expected_confidence: str = "medium",
    promotion: str = "retain",
    promotion_reason: str = "",
    remaining_uncertainty: list[str] | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    captures = []
    for index, finding in enumerate(result.findings, start=1):
        signature = extract_signature(finding)
        expected = {
            key: value
            for key, value in {
                "policy_state": policy_state,
                "classification": expected_classification,
                "calibrated_state": expected_state,
                "confidence": expected_confidence,
                "promotion": promotion,
                "promotion_reason": promotion_reason,
                "remaining_uncertainty": list(remaining_uncertainty or []),
            }.items()
            if value not in ("", [], None)
        }
        captures.append(
            {
                "signature_id": signature_id(signature, policy_state=policy_state, finding_ref=f"F-{index:04d}"),
                "finding_ref": f"F-{index:04d}",
                "host": finding.host,
                "port": finding.port,
                "protocol": finding.protocol,
                "finding_name": finding.name,
                "target_family": signature.get("target_family", target_family_for_finding(finding)),
                "status": finding.status.value,
                "confidence": finding.confidence.value,
                "observed_signature": signature,
                "expected": expected,
                "review": _default_capture_review(expected),
                "raw_evidence": [to_plain(evidence) for evidence in finding.evidence],
            }
        )
    corpus = {
        "metadata": {
            "tool": "RelayX",
            "version": __version__,
            "schema_version": 1,
            "mode": "lab_signature_corpus",
            "captured_at": datetime.now(UTC).isoformat(),
            "label": label,
            "environment": environment,
            "policy_state": policy_state,
            "source_result_version": result.metadata.version,
            "active_probe": result.metadata.active,
            "finding_count": len(captures),
        },
        "opsec": {
            "network_actions_recorded": bool(result.metadata.active),
            "notes": list(notes or []),
            "limitations": [
                "The corpus is an offline record of observed signatures; it does not by itself prove relayability.",
                "Promote profile states only after the same signature is stable across repeated lab captures.",
            ],
        },
        "provenance": _default_provenance(label=label),
        "endpoint_build": _default_endpoint_build(policy_state=policy_state),
        "drift_baseline": _default_drift_baseline(label=label, policy_state=policy_state),
        "captures": captures,
    }
    return normalize_corpus(corpus)


def corpus_to_profile(
    corpuses: list[dict[str, Any]],
    *,
    profile_id: str,
    target_family: str,
    service: str = "",
    description: str = "",
    min_captures: int = 1,
    stable_threshold: float = 0.85,
) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    discriminators: set[str] = set()
    seen_names: set[str] = set()
    stability = assess_lab_stability(
        corpuses,
        target_family=target_family,
        min_captures=min_captures,
        stable_threshold=stable_threshold,
    )
    stability_by_state = {
        str(row.get("policy_state") or ""): row
        for row in stability.get("policy_states", [])
    }
    for corpus in corpuses:
        metadata = corpus.get("metadata", {})
        for capture in corpus.get("captures", []):
            if capture.get("target_family") != target_family:
                continue
            signature = dict(capture.get("observed_signature") or {})
            expected = dict(capture.get("expected") or {})
            match = _profile_match_from_signature(signature)
            if not match:
                continue
            discriminators.update(match)
            policy_state = str(expected.get("policy_state") or metadata.get("policy_state") or "observed")
            calibrated_state = str(
                expected.get("calibrated_state")
                or expected.get("classification")
                or signature.get("response_classification")
                or policy_state
            )
            promotion = str(expected.get("promotion") or "retain")
            confidence = str(expected.get("confidence") or capture.get("confidence") or "medium")
            group_key = json.dumps(
                {
                    "match": match,
                    "calibrated_state": calibrated_state,
                    "promotion": promotion,
                    "confidence": confidence,
                },
                sort_keys=True,
            )
            row = grouped.setdefault(
                group_key,
                {
                    "policy_states": set(),
                    "corpus_labels": set(),
                    "capture_refs": [],
                    "provenance_blocks": [],
                    "signature_ids": set(),
                    "remaining_uncertainty": [],
                    "promotion_reasons": [],
                    "match": match,
                    "calibrated_state": calibrated_state,
                    "confidence": confidence,
                    "promotion": promotion,
                },
            )
            row["policy_states"].add(policy_state)
            if metadata.get("label"):
                row["corpus_labels"].add(str(metadata["label"]))
            row["capture_refs"].append(
                _capture_ref(capture, metadata=metadata)
            )
            if promotion in {"promote", "block"} and not _capture_promotion_ready(corpus, capture):
                row["provenance_blocks"].append(
                    {
                        "capture": _capture_ref(capture, metadata=metadata),
                        "reasons": _capture_review_reasons(corpus, capture, promotion_ready=False),
                    }
                )
            if capture.get("signature_id"):
                row["signature_ids"].add(str(capture["signature_id"]))
            for item in _string_list(expected.get("remaining_uncertainty", [])):
                if item not in row["remaining_uncertainty"]:
                    row["remaining_uncertainty"].append(item)
            reason = str(expected.get("promotion_reason") or "").strip()
            if reason and reason not in row["promotion_reasons"]:
                row["promotion_reasons"].append(reason)
    states: list[dict[str, Any]] = []
    min_required = max(1, int(min_captures))
    for row in sorted(grouped.values(), key=lambda item: (sorted(item["policy_states"]), item["calibrated_state"])):
        policy_label = "_".join(sorted(row["policy_states"])) or "observed"
        name = _unique_state_name(policy_label, seen_names)
        original_promotion = row["promotion"]
        promotion = original_promotion
        limitations = list(row["remaining_uncertainty"])
        stability_rows = [
            stability_by_state[state]
            for state in sorted(row["policy_states"])
            if state in stability_by_state
        ]
        if row["capture_refs"] and len(row["capture_refs"]) < min_required and promotion == "promote":
            promotion = "retain"
            limitations.append(
                f"Promotion suppressed because capture_count={len(row['capture_refs'])} is below min_captures={min_required}."
            )
        blocking_stability = [
            state
            for state in stability_rows
            if state.get("status") != "stable"
            or state.get("drift_detected")
            or state.get("missing_signature_keys")
        ]
        if original_promotion == "promote" and blocking_stability:
            promotion = "retain"
            states_text = ", ".join(
                f"{state['policy_state']}={state['status']}"
                for state in blocking_stability
            )
            limitations.append(
                "Promotion suppressed because repeat-capture stability is not proven "
                f"for {states_text}."
            )
        if original_promotion in {"promote", "block"} and row["provenance_blocks"]:
            promotion = "retain"
            limitations.append(
                "Promotion suppressed because source captures are not promotion-ready under the lab provenance review contract."
            )
            for block in row["provenance_blocks"]:
                for reason in block.get("reasons", []):
                    limitations.append(f"Provenance gate: {reason}")
        limitations.extend(
            [
                "Generated profile state; validate against repeated lab captures before relying on promotion.",
                "Review raw_evidence in the source corpus for endpoint-specific behavior.",
            ]
        )
        states.append(
            {
                "name": name,
                "calibrated_state": row["calibrated_state"],
                "confidence": row["confidence"],
                "promotion": promotion,
                "why": " ".join(row["promotion_reasons"]) or "Generated from RelayX lab signature corpus.",
                "match": row["match"],
                "limitations": _dedupe_strings(limitations),
                "capture_count": len(row["capture_refs"]),
                "source_captures": row["capture_refs"],
                "source_signature_ids": sorted(row["signature_ids"]),
            }
        )
    return {
        "profile_id": profile_id,
        "target_family": target_family,
        "service": service,
        "description": description or f"Generated RelayX calibration profile for {target_family}.",
        "discriminators": sorted(discriminators),
        "states": states,
        "source_corpus": {
            "corpus_count": len(corpuses),
            "capture_count": sum(len(corpus.get("captures", [])) for corpus in corpuses),
            "target_family_capture_count": sum(
                1
                for corpus in corpuses
                for capture in corpus.get("captures", [])
                if capture.get("target_family") == target_family
            ),
            "min_captures": min_required,
            "stable_threshold": _bounded_threshold(stable_threshold),
            "stability_status": stability.get("status"),
        },
    }


def load_corpus_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"lab corpus {path} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict) or "captures" not in data:
        raise ValueError(f"lab corpus {path} must be a RelayX corpus object with captures")
    return normalize_corpus(data, source_path=str(path))


def load_corpuses(paths: list[str]) -> list[dict[str, Any]]:
    corpuses: list[dict[str, Any]] = []
    for path in paths:
        root = Path(path)
        if not root.exists():
            raise ValueError(f"lab corpus path does not exist: {path}")
        if root.is_dir():
            files = sorted(item for item in root.glob("*.json") if item.is_file())
        else:
            files = [root]
        for file_path in files:
            corpuses.append(load_corpus_file(file_path))
    return corpuses


def normalize_corpus(corpus: dict[str, Any], *, source_path: str = "") -> dict[str, Any]:
    metadata = corpus.setdefault("metadata", {})
    metadata.setdefault("tool", "RelayX")
    metadata.setdefault("version", __version__)
    metadata.setdefault("schema_version", 1)
    metadata.setdefault("mode", "lab_signature_corpus")
    if source_path:
        metadata.setdefault("source_path", source_path)
    provenance = corpus.get("provenance")
    if not isinstance(provenance, dict):
        provenance = _default_provenance(label=str(metadata.get("label") or ""))
        corpus["provenance"] = provenance
    else:
        _fill_missing(provenance, _default_provenance(label=str(metadata.get("label") or "")))
    endpoint_build = corpus.get("endpoint_build")
    if not isinstance(endpoint_build, dict):
        endpoint_build = _default_endpoint_build(policy_state=str(metadata.get("policy_state") or ""))
        corpus["endpoint_build"] = endpoint_build
    else:
        _fill_missing(endpoint_build, _default_endpoint_build(policy_state=str(metadata.get("policy_state") or "")))
    drift_baseline = corpus.get("drift_baseline")
    if not isinstance(drift_baseline, dict):
        drift_baseline = _default_drift_baseline(
            label=str(metadata.get("label") or ""),
            policy_state=str(metadata.get("policy_state") or ""),
        )
        corpus["drift_baseline"] = drift_baseline
    else:
        _fill_missing(
            drift_baseline,
            _default_drift_baseline(
                label=str(metadata.get("label") or ""),
                policy_state=str(metadata.get("policy_state") or ""),
            ),
        )
    captures = corpus.get("captures")
    if not isinstance(captures, list):
        raise ValueError(f"lab corpus {source_path or '<memory>'} field 'captures' must be a list")
    for index, capture in enumerate(captures, start=1):
        if not isinstance(capture, dict):
            raise ValueError(f"lab corpus {source_path or '<memory>'} capture {index} must be an object")
        capture.setdefault("finding_ref", f"F-{index:04d}")
        capture.setdefault("expected", {})
        signature = capture.get("observed_signature") or {}
        if isinstance(signature, dict):
            capture.setdefault(
                "signature_id",
                signature_id(
                    signature,
                    policy_state=str((capture.get("expected") or {}).get("policy_state") or metadata.get("policy_state") or ""),
                    finding_ref=str(capture.get("finding_ref") or f"F-{index:04d}"),
                ),
            )
        review = capture.get("review")
        if not isinstance(review, dict):
            capture["review"] = _default_capture_review(capture.get("expected") or {})
        else:
            _fill_missing(review, _default_capture_review(capture.get("expected") or {}))
    metadata["finding_count"] = len(captures)
    corpus.setdefault(
        "opsec",
        {
            "network_actions_recorded": bool(metadata.get("active_probe", False)),
            "notes": [],
            "limitations": [
                "The corpus is an offline record of observed signatures; it does not by itself prove relayability."
            ],
        },
    )
    return corpus


def summarize_corpuses(corpuses: list[dict[str, Any]], *, target_family: str = "") -> dict[str, Any]:
    family_rows: dict[str, dict[str, Any]] = {}
    promotion_counts: Counter[str] = Counter()
    state_counts: Counter[str] = Counter()
    signature_groups: dict[str, dict[str, Any]] = {}
    for corpus in corpuses:
        normalized = normalize_corpus(corpus)
        metadata = normalized.get("metadata", {})
        label = str(metadata.get("label") or metadata.get("source_path") or "corpus")
        for capture in normalized.get("captures", []):
            family = str(capture.get("target_family") or "")
            if target_family and family != target_family:
                continue
            expected = capture.get("expected") or {}
            policy_state = str(expected.get("policy_state") or metadata.get("policy_state") or "observed")
            promotion = str(expected.get("promotion") or "retain")
            calibrated_state = str(expected.get("calibrated_state") or expected.get("classification") or "unclassified")
            promotion_counts[promotion] += 1
            state_counts[policy_state] += 1
            family_row = family_rows.setdefault(
                family,
                {
                    "target_family": family,
                    "captures": 0,
                    "policy_states": Counter(),
                    "calibrated_states": Counter(),
                    "promotions": Counter(),
                    "environments": Counter(),
                    "response_classifications": Counter(),
                },
            )
            family_row["captures"] += 1
            family_row["policy_states"][policy_state] += 1
            family_row["calibrated_states"][calibrated_state] += 1
            family_row["promotions"][promotion] += 1
            if metadata.get("environment"):
                family_row["environments"][str(metadata["environment"])] += 1
            classification = str((capture.get("observed_signature") or {}).get("response_classification") or "not_available")
            family_row["response_classifications"][classification] += 1
            group_key = _signature_group_key(capture)
            group = signature_groups.setdefault(
                group_key,
                {
                    "target_family": family,
                    "capture_count": 0,
                    "policy_states": set(),
                    "promotion": promotion,
                    "calibrated_state": calibrated_state,
                    "signature_ids": set(),
                    "corpus_labels": set(),
                    "remaining_uncertainty": [],
                },
            )
            group["capture_count"] += 1
            group["policy_states"].add(policy_state)
            group["corpus_labels"].add(label)
            if capture.get("signature_id"):
                group["signature_ids"].add(str(capture["signature_id"]))
            for item in _string_list(expected.get("remaining_uncertainty", [])):
                if item not in group["remaining_uncertainty"]:
                    group["remaining_uncertainty"].append(item)
    families = []
    for family, row in sorted(family_rows.items()):
        families.append(
            {
                "target_family": family,
                "captures": row["captures"],
                "policy_states": dict(sorted(row["policy_states"].items())),
                "calibrated_states": dict(sorted(row["calibrated_states"].items())),
                "promotions": dict(sorted(row["promotions"].items())),
                "environments": dict(sorted(row["environments"].items())),
                "response_classifications": dict(sorted(row["response_classifications"].items())),
            }
        )
    groups = [
        {
            "target_family": group["target_family"],
            "capture_count": group["capture_count"],
            "policy_states": sorted(group["policy_states"]),
            "promotion": group["promotion"],
            "calibrated_state": group["calibrated_state"],
            "signature_ids": sorted(group["signature_ids"]),
            "corpus_labels": sorted(group["corpus_labels"]),
            "remaining_uncertainty": group["remaining_uncertainty"],
        }
        for group in sorted(signature_groups.values(), key=lambda item: (item["target_family"], item["calibrated_state"], item["promotion"]))
    ]
    return {
        "name": "RelayX lab corpus index",
        "version": 1,
        "schema_version": 1,
        "corpus_count": len(corpuses),
        "capture_count": sum(row["captures"] for row in families),
        "target_family": target_family,
        "promotion_counts": dict(sorted(promotion_counts.items())),
        "policy_state_counts": dict(sorted(state_counts.items())),
        "families": families,
        "signature_groups": groups,
    }


def assess_lab_provenance(
    corpuses: list[dict[str, Any]],
    *,
    target_family: str = "",
) -> dict[str, Any]:
    normalized = [normalize_corpus(corpus) for corpus in corpuses]
    corpus_rows: list[dict[str, Any]] = []
    capture_reviews: list[dict[str, Any]] = []
    promotion_blocks: list[dict[str, Any]] = []
    for corpus in normalized:
        row = _corpus_provenance_row(corpus, target_family=target_family)
        corpus_rows.append(row)
        for capture in corpus.get("captures", []):
            if target_family and capture.get("target_family") != target_family:
                continue
            review_row = _capture_review_row(corpus, capture)
            capture_reviews.append(review_row)
            if review_row["expected_promotion"] in {"promote", "block"} and not review_row["promotion_ready"]:
                promotion_blocks.append(
                    {
                        "corpus": review_row["corpus"],
                        "finding_ref": review_row["finding_ref"],
                        "target_family": review_row["target_family"],
                        "policy_state": review_row["policy_state"],
                        "expected_promotion": review_row["expected_promotion"],
                        "reasons": review_row["reasons"],
                    }
                )

    failing = [row for row in corpus_rows if row["status"] == "fail"]
    warning = [row for row in corpus_rows if row["status"] == "warn"]
    real_unreviewed_promotions = [
        row
        for row in capture_reviews
        if row["expected_promotion"] in {"promote", "block"}
        and row["data_origin"] != "synthetic"
        and not row["promotion_ready"]
    ]
    status = "pass"
    if failing:
        status = "fail"
    elif warning or real_unreviewed_promotions:
        status = "warn"
    return {
        "name": "RelayX lab corpus provenance",
        "version": 1,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "status": status,
        "target_family": target_family,
        "summary": {
            "corpuses": len(corpus_rows),
            "captures": len(capture_reviews),
            "synthetic_corpuses": sum(1 for row in corpus_rows if row["data_origin"] == "synthetic"),
            "operator_supplied_corpuses": sum(1 for row in corpus_rows if row["data_origin"] == "operator_supplied"),
            "real_lab_corpuses": sum(1 for row in corpus_rows if row["data_origin"] == "real_lab"),
            "external_corpuses": sum(1 for row in corpus_rows if row["data_origin"] == "external"),
            "missing_provenance": sum(1 for row in corpus_rows if row["missing_provenance_keys"]),
            "missing_endpoint_build": sum(1 for row in corpus_rows if row["missing_endpoint_build_keys"]),
            "missing_drift_baseline": sum(1 for row in corpus_rows if row["missing_drift_baseline_keys"]),
            "promotion_hints": sum(1 for row in capture_reviews if row["expected_promotion"] in {"promote", "block"}),
            "promotion_ready": sum(1 for row in capture_reviews if row["promotion_ready"]),
            "unreviewed_promotion_hints": len(real_unreviewed_promotions),
            "fixture_only_promotion_hints": sum(
                1
                for row in capture_reviews
                if row["expected_promotion"] in {"promote", "block"} and row["data_origin"] == "synthetic"
            ),
            "pending_reviews": sum(1 for row in capture_reviews if row["review_status"] == "pending_review"),
            "reviewed_captures": sum(
                1
                for row in capture_reviews
                if row["review_status"] in {"operator_reviewed", "promotion_approved", "promotion_rejected", "fixture_only"}
            ),
        },
        "corpuses": corpus_rows,
        "capture_reviews": capture_reviews,
        "promotion_blocks": promotion_blocks,
        "confidence_contract": {
            "version": 1,
            "evidence_model": "lab_corpus_provenance_review",
            "status_rule": "fail when required provenance, endpoint build, or drift baseline structure is absent; warn when non-synthetic promotion hints lack operator review.",
            "promotion_boundary": "A corpus can support promotion only when it is non-synthetic, endpoint build metadata is present, drift baseline metadata is present, and the capture-level review explicitly approves the promotion or blocking decision.",
            "synthetic_boundary": "Bundled synthetic fixtures can exercise schemas and differentials, but they are not treated as real lab promotion evidence.",
            "remaining_uncertainty": [
                "Operator-reviewed lab evidence still needs protocol-specific stability and differential checks before profile promotion.",
                "Endpoint build metadata should be refreshed after server patching, authentication provider changes, localization changes, or policy changes.",
            ],
        },
    }


def render_lab_provenance(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "RelayX Lab Corpus Provenance",
        "",
        f"Status       : {report['status']}",
        f"Corpuses     : {summary['corpuses']}",
        f"Captures     : {summary['captures']}",
        f"Origins      : synthetic={summary['synthetic_corpuses']} operator={summary['operator_supplied_corpuses']} real_lab={summary['real_lab_corpuses']} external={summary['external_corpuses']}",
        f"Promotion    : ready={summary['promotion_ready']} not_ready={len(report.get('promotion_blocks', []))} hints={summary['promotion_hints']}",
        f"Review       : pending={summary['pending_reviews']} reviewed={summary['reviewed_captures']}",
    ]
    if report.get("target_family"):
        lines.append(f"Filter       : {report['target_family']}")
    lines.extend(["", "Corpuses:"])
    for row in report.get("corpuses", []):
        lines.append(
            f"  - {row['status']}: {row['corpus']} kind={row['corpus_kind']} origin={row['data_origin']} "
            f"review={row['review_status']} captures={row['capture_count']}"
        )
        if row.get("missing_provenance_keys"):
            lines.append(f"    missing_provenance: {', '.join(row['missing_provenance_keys'])}")
        if row.get("missing_endpoint_build_keys"):
            lines.append(f"    missing_endpoint_build: {', '.join(row['missing_endpoint_build_keys'])}")
        if row.get("missing_drift_baseline_keys"):
            lines.append(f"    missing_drift_baseline: {', '.join(row['missing_drift_baseline_keys'])}")
        for reason in row.get("reasons", []):
            lines.append(f"    why: {reason}")
    if report.get("promotion_blocks"):
        lines.extend(["", "Promotion Blocks:"])
        for block in report["promotion_blocks"]:
            lines.append(
                f"  - {block['corpus']} {block['finding_ref']} policy={block['policy_state']} "
                f"promotion={block['expected_promotion']}"
            )
            for reason in block.get("reasons", []):
                lines.append(f"    why: {reason}")
    return "\n".join(lines)


def standard_lab_matrix(*, target_family: str = "") -> dict[str, Any]:
    rows = [
        dict(row)
        for row in _STANDARD_LAB_MATRIX
        if not target_family or row["target_family"] == target_family
    ]
    families: dict[str, dict[str, Any]] = {}
    for row in rows:
        family = families.setdefault(
            row["target_family"],
            {
                "target_family": row["target_family"],
                "required_states": 0,
                "policy_states": [],
                "services": set(),
            },
        )
        if row.get("required", True):
            family["required_states"] += 1
        family["policy_states"].append(row["policy_state"])
        family["services"].add(row["service"])
    return {
        "name": "RelayX standard lab matrix",
        "version": LAB_MATRIX_VERSION,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "target_family": target_family,
        "summary": {
            "families": len(families),
            "requirements": len(rows),
            "required_states": sum(1 for row in rows if row.get("required", True)),
        },
        "families": [
            {
                **{key: value for key, value in family.items() if key != "services"},
                "services": sorted(family["services"]),
                "policy_states": sorted(family["policy_states"]),
            }
            for family in sorted(families.values(), key=lambda item: item["target_family"])
        ],
        "requirements": rows,
        "confidence_contract": {
            "version": 2,
            "evidence_model": "lab_matrix_policy_state_coverage",
            "promotion_boundary": "A policy state can be promoted only when a reviewed lab profile or baseline differential matches stable discriminators.",
            "required_capture_fields": [
                "target_family",
                "expected.policy_state",
                "observed_signature",
                "raw_evidence",
            ],
            "required_output_fields": [
                "coverage.status",
                "coverage.capture_count",
                "coverage.missing_signature_keys",
                "coverage.confidence_counts",
                "coverage.promotion_counts",
            ],
        },
    }


def verify_lab_corpus(
    corpuses: list[dict[str, Any]],
    *,
    target_family: str = "",
    min_captures: int = 1,
) -> dict[str, Any]:
    normalized = [normalize_corpus(corpus) for corpus in corpuses]
    matrix = standard_lab_matrix(target_family=target_family)
    min_required = max(1, int(min_captures))
    captures_by_state: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for corpus in normalized:
        metadata = corpus.get("metadata", {})
        for capture in corpus.get("captures", []):
            family = str(capture.get("target_family") or "")
            policy_state = _capture_policy_state(capture, metadata)
            captures_by_state.setdefault((family, policy_state), []).append(capture)

    coverage = []
    missing_required: list[dict[str, Any]] = []
    incomplete_required: list[dict[str, Any]] = []
    for requirement in matrix["requirements"]:
        family = requirement["target_family"]
        policy_state = requirement["policy_state"]
        captures = captures_by_state.get((family, policy_state), [])
        missing_signature_keys = sorted(
            {
                key
                for capture in captures
                for key in _missing_signature_keys(capture, requirement.get("required_signature_keys", []))
            }
        )
        status = "pass"
        if not captures:
            status = "missing"
        elif len(captures) < min_required or missing_signature_keys:
            status = "incomplete"
        row = {
            "id": requirement["id"],
            "target_family": family,
            "policy_state": policy_state,
            "required": bool(requirement.get("required", True)),
            "status": status,
            "capture_count": len(captures),
            "min_captures": min_required,
            "missing_signature_keys": missing_signature_keys,
            "capture_refs": [_capture_ref(capture, metadata=_capture_metadata_for(capture, normalized)) for capture in captures],
            "confidence_counts": dict(sorted(Counter(str(capture.get("confidence") or "unknown") for capture in captures).items())),
            "promotion_counts": dict(
                sorted(Counter(str((capture.get("expected") or {}).get("promotion") or "retain") for capture in captures).items())
            ),
            "required_signature_keys": list(requirement.get("required_signature_keys", [])),
            "promotion_expectation": requirement.get("promotion_expectation", ""),
            "why": requirement.get("why", ""),
            "remaining_uncertainty": list(requirement.get("remaining_uncertainty", [])),
        }
        coverage.append(row)
        if row["required"] and status == "missing":
            missing_required.append(row)
        elif row["required"] and status == "incomplete":
            incomplete_required.append(row)

    status = "pass"
    if missing_required:
        status = "fail"
    elif incomplete_required:
        status = "warn"
    return {
        "name": "RelayX lab corpus verification",
        "version": 2,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "status": status,
        "target_family": target_family,
        "summary": {
            "corpuses": len(normalized),
            "captures": sum(len(corpus.get("captures", [])) for corpus in normalized),
            "requirements": len(coverage),
            "passed": sum(1 for row in coverage if row["status"] == "pass"),
            "missing": len(missing_required),
            "incomplete": len(incomplete_required),
            "min_captures": min_required,
        },
        "coverage": coverage,
        "missing_required": missing_required,
        "incomplete_required": incomplete_required,
        "confidence_contract": {
            "version": 2,
            "evidence_model": "lab_corpus_coverage",
            "status_rule": "fail when a required state is missing; warn when a required state lacks enough captures or required signature keys.",
            "promotion_boundary": "Coverage verifies lab corpus completeness; it does not promote findings by itself.",
            "remaining_uncertainty": [
                "Repeated captures in a real lab are still required before production-facing confidence is raised.",
                "Endpoint-specific response wording must be reviewed before generated profiles are trusted.",
            ],
        },
    }


def assess_lab_stability(
    corpuses: list[dict[str, Any]],
    *,
    target_family: str = "",
    min_captures: int = 2,
    stable_threshold: float = 0.85,
) -> dict[str, Any]:
    normalized = [normalize_corpus(corpus) for corpus in corpuses]
    matrix = standard_lab_matrix(target_family=target_family)
    min_required = max(1, int(min_captures))
    threshold = _bounded_threshold(stable_threshold)
    captures_by_state: dict[tuple[str, str], list[dict[str, Any]]] = {}
    metadata_by_capture: dict[int, dict[str, Any]] = {}
    for corpus in normalized:
        metadata = corpus.get("metadata", {})
        for capture in corpus.get("captures", []):
            family = str(capture.get("target_family") or "")
            if target_family and family != target_family:
                continue
            policy_state = _capture_policy_state(capture, metadata)
            captures_by_state.setdefault((family, policy_state), []).append(capture)
            metadata_by_capture[id(capture)] = metadata

    rows: list[dict[str, Any]] = []
    for requirement in matrix["requirements"]:
        family = str(requirement["target_family"])
        policy_state = str(requirement["policy_state"])
        captures = captures_by_state.get((family, policy_state), [])
        rows.append(
            _stability_row(
                requirement,
                captures,
                metadata_by_capture=metadata_by_capture,
                min_captures=min_required,
                stable_threshold=threshold,
            )
        )

    observed_keys = set(captures_by_state)
    matrix_keys = {
        (str(row["target_family"]), str(row["policy_state"]))
        for row in matrix["requirements"]
    }
    for family, policy_state in sorted(observed_keys - matrix_keys):
        captures = captures_by_state[(family, policy_state)]
        rows.append(
            _stability_row(
                {
                    "id": f"OBSERVED-{family.upper()}-{policy_state.upper()}",
                    "target_family": family,
                    "policy_state": policy_state,
                    "required": False,
                    "required_signature_keys": [],
                    "promotion_expectation": "review",
                    "why": "Observed corpus state is not part of the standard RelayX lab matrix.",
                    "remaining_uncertainty": [
                        "Add this state to the lab matrix or treat it as an endpoint-specific extension."
                    ],
                },
                captures,
                metadata_by_capture=metadata_by_capture,
                min_captures=min_required,
                stable_threshold=threshold,
            )
        )

    required_rows = [row for row in rows if row.get("required", True)]
    missing = [row for row in required_rows if row["status"] == "missing"]
    insufficient = [row for row in required_rows if row["status"] == "insufficient"]
    drifted = [row for row in required_rows if row["drift_detected"]]
    unstable = [row for row in required_rows if row["status"] == "drift"]
    status = "pass"
    if missing:
        status = "fail"
    elif insufficient or unstable:
        status = "warn"
    scores = [float(row["consistency_score"]) for row in rows if row["capture_count"]]
    return {
        "name": "RelayX lab capture stability",
        "version": 1,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "status": status,
        "target_family": target_family,
        "summary": {
            "corpuses": len(normalized),
            "captures": sum(len(corpus.get("captures", [])) for corpus in normalized),
            "policy_states": len(rows),
            "stable": sum(1 for row in rows if row["status"] == "stable"),
            "missing": len(missing),
            "insufficient": len(insufficient),
            "drifted": len(drifted),
            "min_captures": min_required,
            "stable_threshold": threshold,
            "average_consistency_score": round(sum(scores) / len(scores), 4) if scores else 0.0,
        },
        "policy_states": rows,
        "promotion_downgrades": [
            {
                "target_family": row["target_family"],
                "policy_state": row["policy_state"],
                "recommended_profile_promotion": row["recommended_profile_promotion"],
                "reasons": row["promotion_downgrade_reasons"],
            }
            for row in rows
            if row["promotion_downgrade_reasons"]
        ],
        "confidence_contract": {
            "version": 3,
            "evidence_model": "repeat_capture_stability",
            "status_rule": "fail when a required state is missing; warn when repeated captures are insufficient or drift is detected.",
            "consistency_rule": "consistency_score is the dominant stable-signature ratio within one target_family and policy_state.",
            "promotion_boundary": "A promotable lab state remains promotable only when required signature keys are present, repeated captures meet min_captures, and the stable signature ratio meets stable_threshold.",
            "auto_downgrade_rule": "Promote or block hints are downgraded to retain when coverage, signature-key, or repeat-capture stability gates are not satisfied.",
            "remaining_uncertainty": [
                "Stable lab signatures refine policy inference; they do not by themselves prove live relay execution success.",
                "Capture stability should be rechecked after server patching, provider changes, localization changes, and authentication package changes.",
            ],
        },
    }


def render_lab_stability(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "RelayX Lab Capture Stability",
        "",
        f"Status       : {report['status']}",
        f"Corpuses     : {summary['corpuses']}",
        f"Captures     : {summary['captures']}",
        f"Policy States: {summary['stable']}/{summary['policy_states']} stable",
        f"Issues       : {summary['missing']} missing, {summary['insufficient']} insufficient, {summary['drifted']} drifted",
        f"Threshold    : min_captures={summary['min_captures']} stable_threshold={summary['stable_threshold']}",
        f"Avg Score    : {summary['average_consistency_score']}",
    ]
    if report.get("target_family"):
        lines.append(f"Filter       : {report['target_family']}")
    lines.extend(["", "Policy States:"])
    for row in report.get("policy_states", []):
        lines.append(
            f"  - {row['status']}: {row['target_family']} policy={row['policy_state']} "
            f"captures={row['capture_count']} score={row['consistency_score']} "
            f"promotion={row['recommended_profile_promotion']}"
        )
        if row.get("dominant_signature_id"):
            lines.append(f"    dominant_signature: {row['dominant_signature_id']}")
        if row.get("drift_keys"):
            lines.append(f"    drift_keys: {', '.join(row['drift_keys'])}")
        if row.get("missing_signature_keys"):
            lines.append(f"    missing_signature_keys: {', '.join(row['missing_signature_keys'])}")
        for reason in row.get("promotion_downgrade_reasons", []):
            lines.append(f"    downgrade: {reason}")
    return "\n".join(lines)


def assess_lab_differentials(
    corpuses: list[dict[str, Any]],
    *,
    target_family: str = "",
    min_captures: int = 2,
    stable_threshold: float = 0.85,
    pairs: list[str] | None = None,
) -> dict[str, Any]:
    stability = assess_lab_stability(
        corpuses,
        target_family=target_family,
        min_captures=min_captures,
        stable_threshold=stable_threshold,
    )
    matrix = standard_lab_matrix(target_family=target_family)
    rows_by_state = {
        (str(row.get("target_family") or ""), str(row.get("policy_state") or "")): row
        for row in stability.get("policy_states", [])
    }
    pair_filters = [str(item).strip().lower() for item in (pairs or []) if str(item).strip()]
    matched_pair_filters: set[str] = set()
    comparisons: list[dict[str, Any]] = []
    for left_req, right_req in _lab_differential_pairs(matrix.get("requirements", [])):
        family = str(left_req["target_family"])
        left_state = str(left_req["policy_state"])
        right_state = str(right_req["policy_state"])
        matched_filters = _matched_pair_filters(pair_filters, family, left_state, right_state)
        if pair_filters and not matched_filters:
            continue
        matched_pair_filters.update(matched_filters)
        left = rows_by_state.get((family, left_state), _missing_differential_state(left_req, min_captures, stable_threshold))
        right = rows_by_state.get((family, right_state), _missing_differential_state(right_req, min_captures, stable_threshold))
        comparisons.append(_lab_differential_row(left_req, right_req, left, right))

    missing = [row for row in comparisons if row["status"] == "missing"]
    unstable = [row for row in comparisons if row["status"] in {"insufficient", "unstable"}]
    unmatched_pair_filters = sorted(set(pair_filters) - matched_pair_filters)
    indistinguishable = [
        row
        for row in comparisons
        if row["status"] == "indistinguishable" and row["expected_promotion_relevant"]
    ]
    status = "pass"
    if missing:
        status = "fail"
    elif unstable or indistinguishable or unmatched_pair_filters:
        status = "warn"
    return {
        "name": "RelayX lab response differential",
        "version": 1,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "status": status,
        "target_family": target_family,
        "summary": {
            "pairs": len(comparisons),
            "differential": sum(1 for row in comparisons if row["status"] == "differential"),
            "context_only": sum(1 for row in comparisons if row["status"] == "context_only"),
            "indistinguishable": sum(1 for row in comparisons if row["status"] == "indistinguishable"),
            "missing": len(missing),
            "unstable": len(unstable),
            "promotion_relevant": sum(1 for row in comparisons if row["expected_promotion_relevant"]),
            "promotable_candidates": sum(1 for row in comparisons if row["promotable_candidate"]),
            "pair_filters": len(pair_filters),
            "unmatched_pair_filters": len(unmatched_pair_filters),
            "min_captures": stability["summary"]["min_captures"],
            "stable_threshold": stability["summary"]["stable_threshold"],
        },
        "pair_filters": sorted(pair_filters),
        "unmatched_pair_filters": unmatched_pair_filters,
        "pairs": comparisons,
        "stability_summary": stability.get("summary", {}),
        "confidence_contract": {
            "version": 1,
            "evidence_model": "lab_response_differential",
            "source_model": "dominant repeat-capture signature per target_family and policy_state",
            "status_rule": "fail when a required differential pair is missing; warn when a promotion-relevant pair is unstable or indistinguishable.",
            "promotion_boundary": "A differential can support calibration promotion only when both policy states are stable and response discriminator keys change.",
            "context_boundary": "Protocol, target family, finding name, raw HTTP status, and auth-validation presence are recorded as context and are not treated as policy proof by themselves.",
            "remaining_uncertainty": [
                "Response differentials should be reviewed against server build, localization, authentication provider order, and endpoint path.",
                "A stable response difference supports policy inference; it does not by itself prove live relay execution success.",
            ],
        },
    }


def render_lab_differentials(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "RelayX Lab Response Differential",
        "",
        f"Status       : {report['status']}",
        f"Pairs        : {summary['pairs']}",
        f"Differential : {summary['differential']}",
        f"Context Only : {summary['context_only']}",
        f"Indistinguish: {summary['indistinguishable']}",
        f"Issues       : {summary['missing']} missing, {summary['unstable']} unstable",
        f"Promotable   : {summary['promotable_candidates']}/{summary['promotion_relevant']} promotion-relevant",
        f"Threshold    : min_captures={summary['min_captures']} stable_threshold={summary['stable_threshold']}",
    ]
    if report.get("target_family"):
        lines.append(f"Filter       : {report['target_family']}")
    if report.get("unmatched_pair_filters"):
        lines.append(f"Unmatched    : {', '.join(report['unmatched_pair_filters'])}")
    lines.extend(["", "Pairs:"])
    for row in report.get("pairs", []):
        lines.append(
            f"  - {row['status']}: {row['target_family']} "
            f"{row['left_policy_state']} -> {row['right_policy_state']} "
            f"support={row['promotion_support']} promotable={str(row['promotable_candidate']).lower()}"
        )
        if row.get("discriminator_keys"):
            lines.append(f"    discriminators: {', '.join(row['discriminator_keys'])}")
        if row.get("context_only_keys"):
            lines.append(f"    context_only: {', '.join(row['context_only_keys'])}")
        for reason in row.get("reasons", []):
            lines.append(f"    why: {reason}")
    return "\n".join(lines)


def render_lab_matrix(matrix: dict[str, Any]) -> str:
    lines = [
        "RelayX Standard Lab Matrix",
        "",
        f"Version      : {matrix['version']}",
        f"Requirements : {matrix['summary']['requirements']}",
        f"Families     : {matrix['summary']['families']}",
    ]
    if matrix.get("target_family"):
        lines.append(f"Filter       : {matrix['target_family']}")
    lines.extend(["", "Requirements:"])
    for row in matrix.get("requirements", []):
        lines.append(
            f"  - {row['id']} {row['target_family']} policy={row['policy_state']} service={row['service']}"
        )
        lines.append(f"    mode: {row['command_mode']}")
        lines.append(f"    promotion: {row['promotion_expectation']}")
        lines.append(f"    required_signature_keys: {', '.join(row['required_signature_keys'])}")
        lines.append(f"    why: {row['why']}")
    return "\n".join(lines)


def render_lab_verification(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "RelayX Lab Corpus Verification",
        "",
        f"Status       : {report['status']}",
        f"Corpuses     : {summary['corpuses']}",
        f"Captures     : {summary['captures']}",
        f"Requirements : {summary['passed']}/{summary['requirements']} passed",
        f"Issues       : {summary['missing']} missing, {summary['incomplete']} incomplete",
    ]
    if report.get("target_family"):
        lines.append(f"Filter       : {report['target_family']}")
    lines.extend(["", "Coverage:"])
    for row in report.get("coverage", []):
        lines.append(
            f"  - {row['status']}: {row['id']} policy={row['policy_state']} captures={row['capture_count']}"
        )
        if row.get("missing_signature_keys"):
            lines.append(f"    missing_signature_keys: {', '.join(row['missing_signature_keys'])}")
        if row.get("promotion_counts"):
            lines.append(f"    promotions: {_render_counts(row['promotion_counts'])}")
        if row.get("confidence_counts"):
            lines.append(f"    confidence: {_render_counts(row['confidence_counts'])}")
    return "\n".join(lines)


def render_corpus_index(index: dict[str, Any]) -> str:
    lines = [
        "RelayX Lab Corpus Index",
        "",
        f"Corpuses : {index['corpus_count']}",
        f"Captures : {index['capture_count']}",
    ]
    if index.get("target_family"):
        lines.append(f"Filter   : {index['target_family']}")
    lines.extend(["", "Families:"])
    for family in index.get("families", []):
        lines.append(f"  - {family['target_family']}: captures={family['captures']}")
        lines.append(f"    policy_states: {_render_counts(family['policy_states'])}")
        lines.append(f"    promotions   : {_render_counts(family['promotions'])}")
    lines.extend(["", "Signature Groups:"])
    for group in index.get("signature_groups", []):
        lines.append(
            f"  - {group['target_family']} captures={group['capture_count']} "
            f"promotion={group['promotion']} state={group['calibrated_state']}"
        )
        lines.append(f"    policy_states: {', '.join(group['policy_states']) or '-'}")
        if group.get("remaining_uncertainty"):
            lines.append(f"    uncertainty : {'; '.join(group['remaining_uncertainty'])}")
    return "\n".join(lines)


def render_signature_corpus(corpus: dict[str, Any]) -> str:
    metadata = corpus.get("metadata", {})
    lines = [
        "RelayX Lab Signature Corpus",
        "",
        f"Label       : {metadata.get('label') or '-'}",
        f"Environment : {metadata.get('environment') or '-'}",
        f"Policy State: {metadata.get('policy_state') or '-'}",
        f"Captures    : {metadata.get('finding_count', len(corpus.get('captures', [])))}",
        f"Active Probe : {metadata.get('active_probe')}",
        "",
        "Signatures:",
    ]
    for capture in corpus.get("captures", []):
        signature = capture.get("observed_signature", {})
        lines.append(
            f"  - {capture['finding_ref']} {capture['host']}:{capture['port']}/{capture['protocol']} "
            f"family={capture['target_family']} class={signature.get('response_classification', '-')}"
        )
        expected = capture.get("expected") or {}
        if expected:
            rendered = ", ".join(f"{key}={value}" for key, value in sorted(expected.items()))
            lines.append(f"    expected: {rendered}")
    if corpus.get("opsec", {}).get("limitations"):
        lines.extend(["", "Limitations:"])
        for limitation in corpus["opsec"]["limitations"]:
            lines.append(f"  - {limitation}")
    return "\n".join(lines)


def render_generated_profile(profile: dict[str, Any]) -> str:
    lines = [
        "RelayX Generated Lab Profile",
        "",
        f"Profile ID   : {profile['profile_id']}",
        f"Target Family: {profile['target_family']}",
        f"Service      : {profile.get('service') or '-'}",
        f"States       : {len(profile.get('states', []))}",
        "",
        "States:",
    ]
    for state in profile.get("states", []):
        lines.append(
            f"  - {state['name']}: calibrated_state={state['calibrated_state']} "
            f"promotion={state['promotion']}"
        )
        lines.append(f"    match: {json.dumps(state['match'], sort_keys=True)}")
    return "\n".join(lines)


def compare_findings(
    baseline: Finding,
    candidate: Finding,
    profile: CalibrationProfile,
    baseline_ref: str = "baseline",
    candidate_ref: str = "candidate",
) -> BaselineComparison:
    left = extract_signature(baseline)
    right = extract_signature(candidate)
    keys = sorted(set(profile.discriminators) | set(left) | set(right))
    differences = {
        key: {"baseline": left.get(key), "candidate": right.get(key)}
        for key in keys
        if left.get(key) != right.get(key)
    }
    candidate_decision = calibrate_finding(candidate, profile, finding_ref=candidate_ref)
    changed_discriminators = sorted(key for key in profile.discriminators if left.get(key) != right.get(key))
    promotable = candidate_decision.decision.startswith("promote_") and bool(differences)
    if promotable:
        conclusion = f"Candidate can be promoted to {candidate_decision.calibrated_state}."
        reasons = [
            "Candidate matched a promotable lab profile state.",
            "Baseline and candidate signatures differ on calibrated discriminators.",
            *candidate_decision.reasons,
        ]
        limitations = candidate_decision.limitations
    elif not differences:
        conclusion = "Baseline and candidate signatures are indistinguishable."
        reasons = [
            "No response discriminator changed between the two lab captures.",
            "RelayX cannot promote policy state without a stable differential signal.",
        ]
        limitations = [
            "Collect additional lab captures or add more discriminators to the profile."
        ]
    else:
        conclusion = "Candidate differs from baseline but is not promotable yet."
        reasons = [
            "A response difference was observed.",
            "The candidate did not match a promotable calibrated state.",
            *candidate_decision.reasons,
        ]
        limitations = candidate_decision.limitations
    promotion_gate = {
        "profile_id": profile.profile_id,
        "matched_state": candidate_decision.matched_state,
        "profile_matched": bool(candidate_decision.matched_state),
        "differential_signal": bool(differences),
        "changed_discriminators": changed_discriminators,
        "promotable_state": candidate_decision.decision.startswith("promote_"),
        "decision": "promote" if promotable else "retain",
        "candidate_decision": candidate_decision.decision,
    }
    evidence_chain = _baseline_evidence_chain(
        left,
        right,
        differences=differences,
        changed_discriminators=changed_discriminators,
        candidate_decision=candidate_decision,
        promotion_gate=promotion_gate,
    )
    return BaselineComparison(
        profile_id=profile.profile_id,
        baseline_ref=baseline_ref,
        candidate_ref=candidate_ref,
        target_family=profile.target_family,
        differences=differences,
        conclusion=conclusion,
        promotable=promotable,
        reasons=reasons,
        limitations=limitations,
        evidence_chain=evidence_chain,
        confidence_contract=_baseline_confidence_contract(
            right,
            profile=profile,
            candidate_decision=candidate_decision,
            promotion_gate=promotion_gate,
            limitations=limitations,
        ),
    )


def apply_calibration_to_result(result: ScanResult, calibration: dict[str, Any]) -> ScanResult:
    decisions = {
        decision["finding_ref"]: decision
        for decision in calibration.get("decisions", [])
    }
    for index, finding in enumerate(result.findings, start=1):
        decision = decisions.get(f"F-{index:04d}")
        if not decision:
            continue
        finding.evidence.append(
            Evidence(
                EvidenceType.INFERRED,
                "relayx_lab_calibration",
                decision["calibrated_state"],
                Confidence(decision["confidence"]),
                raw=decision,
                detail="RelayX lab calibration decision.",
            )
        )
        if decision["decision"].startswith("promote_"):
            finding.summary += f" Lab calibration: {decision['calibrated_state']}."
    return result


def extract_signature(finding: Finding) -> dict[str, Any]:
    evidence = {item.key: item for item in finding.evidence}
    response = _response_validation(evidence)
    signature = {
        "target_family": target_family_for_finding(finding),
        "protocol": finding.protocol,
        "finding_name": finding.name,
        "response_classification": _evidence_value(evidence, "relayx_response_classification", ""),
        "response_subclassification": _evidence_value(evidence, "relayx_response_subclassification", ""),
        "policy_inference": _evidence_value(evidence, "relayx_policy_inference", ""),
        "oracle_signature": _evidence_value(evidence, "relayx_oracle_signature", ""),
        "auth_validation_observed": _auth_validation_observed(evidence),
        "http_status": _evidence_value(evidence, "http_status"),
        "http_auth_status": response.get("status_code"),
        "ldap_result_code": response.get("result_code"),
        "ldap_diagnostic_contains_80090346": "80090346" in str(response.get("diagnostic_message", "")).lower(),
        "mssql_errors": response.get("errors", []),
        "mssql_loginack": response.get("loginack"),
        "tds_prelogin_encryption": _evidence_value(evidence, "tds_prelogin_encryption", ""),
        "tds_wrapped_tls": _evidence_value(evidence, "tds_wrapped_tls"),
        "tls_certificate_observed": bool(_evidence_value(evidence, "tls_certificate_sha256", "")),
        "cbt_hash_observed": bool(response.get("cbt_hash") or _evidence_value(evidence, "mssql_cbt_tls_server_end_point", "")),
        "response_keywords": _keywords(response),
    }
    return {key: value for key, value in signature.items() if value not in (None, "", [])}


def target_family_for_finding(finding: Finding) -> str:
    if finding.name == "adcs_web_enrollment":
        return "adcs_web_enrollment"
    if finding.name == "winrm_http_ntlm":
        return "winrm_ntlm"
    if finding.protocol in {"http", "https"}:
        return "http_iis_epa"
    if finding.protocol == "ldap":
        return "ldap_signing"
    if finding.protocol == "ldaps":
        return "ldaps_cbt"
    if finding.protocol == "mssql":
        return "mssql_epa"
    if finding.protocol == "smb":
        return "smb_signing"
    return finding.protocol


def render_calibration(calibration: dict[str, Any]) -> str:
    decisions = calibration.get("decisions", [])
    if not decisions:
        return "No calibration decisions available."
    lines = ["RelayX Lab Calibration", ""]
    summary = calibration.get("summary", {})
    if summary:
        lines.append(
            "Summary: "
            + ", ".join(f"{key}={value}" for key, value in sorted(summary.items()))
        )
        lines.append("")
    for decision in decisions:
        lines.append(
            f"{decision['finding_ref']} {decision['host']}:{decision['port']}/{decision['protocol']} "
            f"profile={decision['profile_id']} decision={decision['decision']} "
            f"state={decision['calibrated_state']} confidence={decision['confidence']}"
        )
        for reason in decision["reasons"]:
            lines.append(f"  why: {reason}")
        for limitation in decision["limitations"]:
            lines.append(f"  limit: {limitation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_baseline_comparison(comparison: dict[str, Any]) -> str:
    rows = comparison.get("comparisons", [])
    if not rows:
        return "No comparable baseline/candidate findings available."
    lines = ["RelayX Baseline Comparison", ""]
    for row in rows:
        lines.append(
            f"{row['profile_id']} {row['baseline_ref']} -> {row['candidate_ref']} "
            f"promotable={row['promotable']}"
        )
        lines.append(f"  conclusion: {row['conclusion']}")
        if row["differences"]:
            lines.append("  differences:")
            for key, values in sorted(row["differences"].items()):
                lines.append(f"    {key}: {values['baseline']!r} -> {values['candidate']!r}")
        for reason in row["reasons"]:
            lines.append(f"  why: {reason}")
        for limitation in row["limitations"]:
            lines.append(f"  limit: {limitation}")
        chain = row.get("evidence_chain") or {}
        gate = chain.get("promotion_gate") or {}
        if gate:
            lines.append(
                "  gate: "
                f"profile_matched={gate.get('profile_matched')} "
                f"differential_signal={gate.get('differential_signal')} "
                f"decision={gate.get('decision')}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def _confidence_contract(
    signature: dict[str, Any],
    *,
    profile: CalibrationProfile,
    confidence: str,
    decision: str,
    matched_state: str,
    limitations: list[str],
    promotion_gate: dict[str, Any],
) -> dict[str, Any]:
    present_discriminators = [key for key in profile.discriminators if key in signature]
    missing_discriminators = [key for key in profile.discriminators if key not in signature]
    return {
        "version": 2,
        "confidence": confidence,
        "decision": decision,
        "profile_id": profile.profile_id,
        "target_family": profile.target_family,
        "matched_state": matched_state,
        "signature_id": signature_id(signature, policy_state=matched_state or "observed"),
        "evidence_sources": sorted(signature),
        "present_discriminators": present_discriminators,
        "missing_discriminators": missing_discriminators,
        "promotion_gate": promotion_gate,
        "remaining_uncertainty": list(limitations),
        "interpretation_boundary": "Lab calibration refines policy-state judgement; it does not by itself prove relay execution success.",
    }


def _baseline_evidence_chain(
    baseline_signature: dict[str, Any],
    candidate_signature: dict[str, Any],
    *,
    differences: dict[str, dict[str, Any]],
    changed_discriminators: list[str],
    candidate_decision: CalibrationDecision,
    promotion_gate: dict[str, Any],
) -> dict[str, Any]:
    return {
        "version": 2,
        "baseline_signature_id": signature_id(baseline_signature, policy_state="baseline"),
        "candidate_signature_id": signature_id(candidate_signature, policy_state="candidate"),
        "baseline_signature": baseline_signature,
        "candidate_signature": candidate_signature,
        "changed_keys": sorted(differences),
        "changed_discriminators": changed_discriminators,
        "candidate_matched_state": candidate_decision.matched_state,
        "candidate_calibrated_state": candidate_decision.calibrated_state,
        "candidate_decision": candidate_decision.decision,
        "promotion_gate": promotion_gate,
    }


def _baseline_confidence_contract(
    candidate_signature: dict[str, Any],
    *,
    profile: CalibrationProfile,
    candidate_decision: CalibrationDecision,
    promotion_gate: dict[str, Any],
    limitations: list[str],
) -> dict[str, Any]:
    contract = _confidence_contract(
        candidate_signature,
        profile=profile,
        confidence=candidate_decision.confidence,
        decision=candidate_decision.decision,
        matched_state=candidate_decision.matched_state,
        limitations=limitations,
        promotion_gate=promotion_gate,
    )
    contract["comparison_rule"] = "Promotion requires both a promotable candidate lab state and a baseline/candidate differential signal."
    return contract


def _state_matches(signature: dict[str, Any], match: dict[str, Any]) -> bool:
    for key, expected in match.items():
        actual = signature.get(key)
        if isinstance(expected, list):
            if actual not in expected:
                return False
            continue
        if isinstance(expected, dict):
            if not _dict_match(actual, expected):
                return False
            continue
        if actual != expected:
            return False
    return True


def _dict_match(actual: Any, expected: dict[str, Any]) -> bool:
    text = " ".join(str(item) for item in actual) if isinstance(actual, list) else str(actual)
    lowered = text.lower()
    if "contains" in expected:
        values = expected["contains"]
        if isinstance(values, str):
            values = [values]
        return all(str(value).lower() in lowered for value in values)
    if "any_contains" in expected:
        values = expected["any_contains"]
        if isinstance(values, str):
            values = [values]
        return any(str(value).lower() in lowered for value in values)
    return False


def _response_validation(evidence: dict[str, Evidence]) -> dict[str, Any]:
    for key in [
        "ntlm_authenticate_validation",
        "ldap_ntlm_authenticate_validation",
        "mssql_ntlm_authenticate_validation",
    ]:
        item = evidence.get(key)
        if item and item.raw:
            return item.raw
    return {}


def _auth_validation_observed(evidence: dict[str, Evidence]) -> bool:
    for key in [
        "ntlm_authenticate_validation",
        "ldap_ntlm_authenticate_validation",
        "mssql_ntlm_authenticate_validation",
    ]:
        if bool(_evidence_value(evidence, key, False)):
            return True
    return False


def _evidence_value(evidence: dict[str, Evidence], key: str, default: Any = None) -> Any:
    item = evidence.get(key)
    return item.value if item else default


def _keywords(response: dict[str, Any]) -> list[str]:
    text = " ".join(
        [
            str(response.get("reason", "")),
            str(response.get("www_authenticate", "")),
            str(response.get("diagnostic_message", "")),
            " ".join(str(item) for item in response.get("errors", [])),
            " ".join(str(item) for item in response.get("infos", [])),
        ]
    ).lower()
    candidates = {
        "channel_binding": ["channel binding", "channel-binding", "80090346", "sec_e_bad_bindings"],
        "extended_protection": ["extended protection", "epa"],
        "login_failed": ["login failed", "invalid credentials", "logon failure"],
        "stronger_auth": ["strongerauthrequired", "stronger auth", "confidentiality required"],
    }
    return [
        name
        for name, terms in candidates.items()
        if any(term in text for term in terms)
    ]


def _promotion_decision(state: CalibrationState) -> str:
    if state.promotion == "promote":
        return "promote_calibrated_state"
    if state.promotion == "block":
        return "promote_blocking_state"
    return "retain_conservative"


def _merge_limitations(states: list[CalibrationState]) -> list[str]:
    limitations: list[str] = []
    for state in states:
        for limitation in state.limitations:
            if limitation not in limitations:
                limitations.append(limitation)
    return limitations


def _calibration_summary(decisions: list[CalibrationDecision]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for decision in decisions:
        summary[decision.decision] = summary.get(decision.decision, 0) + 1
    return summary


def _default_provenance(*, label: str = "") -> dict[str, Any]:
    return {
        "corpus_kind": "authorized_lab_capture",
        "data_origin": "operator_supplied",
        "capture_source": "relayx_lab_corpus",
        "capture_method": "RelayX result signature extraction",
        "authorization_ref": "",
        "operator": "",
        "review_status": "pending_review",
        "reviewed_by": "",
        "reviewed_at": "",
        "review_reason": (
            "Generated by relayx lab-corpus; operator review is required before promotion."
            if not label
            else f"Generated by relayx lab-corpus for {label}; operator review is required before promotion."
        ),
    }


def _default_endpoint_build(*, policy_state: str = "") -> dict[str, Any]:
    return {
        "platform": "unknown",
        "server_role": "unknown",
        "os_version": "unknown",
        "product": "unknown",
        "product_version": "unknown",
        "policy_matrix": policy_state or "unknown",
        "authentication_provider": "unknown",
        "notes": [
            "Replace unknown endpoint build fields with authorized lab metadata before promotion review."
        ],
    }


def _default_drift_baseline(*, label: str = "", policy_state: str = "") -> dict[str, Any]:
    baseline_seed = {
        "label": label,
        "policy_state": policy_state,
        "version": __version__,
    }
    digest = sha256(json.dumps(baseline_seed, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "baseline_id": "baseline-" + digest[:12],
        "minimum_repeated_captures": 2,
        "stable_required_keys": sorted(_RESPONSE_DIFFERENTIAL_KEYS),
        "known_unstable_keys": sorted(_CONTEXT_ONLY_SIGNATURE_KEYS),
        "notes": [
            "Default drift baseline generated by RelayX; replace with repeated authorized lab captures."
        ],
    }


def _default_capture_review(expected: dict[str, Any]) -> dict[str, Any]:
    promotion = str(expected.get("promotion") or "retain")
    return {
        "status": "pending_review",
        "promotion_decision": "pending" if promotion in {"promote", "block"} else "retain",
        "reviewed_by": "",
        "reviewed_at": "",
        "reason": "Operator review is required before this capture can support promotion.",
        "limitations": [
            "Capture-level review has not approved this signature as promotion evidence."
        ],
    }


def _fill_missing(target: dict[str, Any], defaults: dict[str, Any]) -> None:
    for key, value in defaults.items():
        if key not in target:
            target[key] = value


def _corpus_provenance_row(corpus: dict[str, Any], *, target_family: str = "") -> dict[str, Any]:
    metadata = corpus.get("metadata", {})
    provenance = corpus.get("provenance") if isinstance(corpus.get("provenance"), dict) else {}
    endpoint_build = corpus.get("endpoint_build") if isinstance(corpus.get("endpoint_build"), dict) else {}
    drift_baseline = corpus.get("drift_baseline") if isinstance(corpus.get("drift_baseline"), dict) else {}
    captures = [
        capture
        for capture in corpus.get("captures", [])
        if not target_family or capture.get("target_family") == target_family
    ]
    missing_provenance = _missing_required_keys(provenance, _PROVENANCE_REQUIRED_KEYS)
    missing_endpoint = _missing_required_keys(endpoint_build, _ENDPOINT_BUILD_REQUIRED_KEYS)
    missing_drift = _missing_required_keys(drift_baseline, _DRIFT_BASELINE_REQUIRED_KEYS)
    corpus_kind = str(provenance.get("corpus_kind") or "")
    data_origin = str(provenance.get("data_origin") or "")
    review_status = str(provenance.get("review_status") or "")
    promotion_hints = [
        capture
        for capture in captures
        if str((capture.get("expected") or {}).get("promotion") or "retain") in {"promote", "block"}
    ]
    promotion_ready = [
        capture
        for capture in promotion_hints
        if _capture_promotion_ready(corpus, capture)
    ]
    reasons: list[str] = []
    if data_origin == "synthetic":
        reasons.append("Synthetic corpus is valid for pipeline and differential tests, but it is not real lab promotion evidence.")
    if missing_provenance:
        reasons.append("Required provenance fields are missing.")
    if missing_endpoint:
        reasons.append("Endpoint build metadata is incomplete.")
    if missing_drift:
        reasons.append("Drift baseline metadata is incomplete.")
    has_unready_promotions = len(promotion_ready) < len(promotion_hints)
    if data_origin != "synthetic" and promotion_hints and has_unready_promotions:
        reasons.append("Promotion or blocking hints are present, but no capture-level review approves them.")
    if _endpoint_contains_unknown(endpoint_build) and data_origin in {"real_lab", "operator_supplied", "external"}:
        reasons.append("Endpoint build metadata contains unknown values; treat conclusions as pending review.")
    status = "pass"
    if missing_provenance or missing_endpoint or missing_drift:
        status = "fail"
    elif data_origin != "synthetic" and (promotion_hints and has_unready_promotions or _endpoint_contains_unknown(endpoint_build)):
        status = "warn"
    return {
        "corpus": _corpus_label(metadata),
        "source_path": str(metadata.get("source_path") or ""),
        "status": status,
        "corpus_kind": corpus_kind,
        "data_origin": data_origin,
        "review_status": review_status,
        "capture_source": str(provenance.get("capture_source") or ""),
        "capture_method": str(provenance.get("capture_method") or ""),
        "authorization_ref": str(provenance.get("authorization_ref") or ""),
        "operator": str(provenance.get("operator") or ""),
        "endpoint_build_complete": not missing_endpoint,
        "drift_baseline_complete": not missing_drift,
        "missing_provenance_keys": missing_provenance,
        "missing_endpoint_build_keys": missing_endpoint,
        "missing_drift_baseline_keys": missing_drift,
        "capture_count": len(captures),
        "promotion_hints": len(promotion_hints),
        "promotion_ready": len(promotion_ready),
        "baseline_minimum_repeated_captures": int(drift_baseline.get("minimum_repeated_captures") or 0),
        "reasons": _dedupe_strings(reasons),
    }


def _capture_review_row(corpus: dict[str, Any], capture: dict[str, Any]) -> dict[str, Any]:
    metadata = corpus.get("metadata", {})
    provenance = corpus.get("provenance") if isinstance(corpus.get("provenance"), dict) else {}
    review = capture.get("review") if isinstance(capture.get("review"), dict) else {}
    expected = capture.get("expected") if isinstance(capture.get("expected"), dict) else {}
    promotion = str(expected.get("promotion") or "retain")
    ready = _capture_promotion_ready(corpus, capture)
    reasons = _capture_review_reasons(corpus, capture, promotion_ready=ready)
    return {
        "corpus": _corpus_label(metadata),
        "finding_ref": str(capture.get("finding_ref") or ""),
        "signature_id": str(capture.get("signature_id") or ""),
        "target_family": str(capture.get("target_family") or ""),
        "policy_state": _capture_policy_state(capture, metadata),
        "expected_promotion": promotion,
        "data_origin": str(provenance.get("data_origin") or ""),
        "review_status": str(review.get("status") or ""),
        "promotion_decision": str(review.get("promotion_decision") or ""),
        "reviewed_by": str(review.get("reviewed_by") or ""),
        "reviewed_at": str(review.get("reviewed_at") or ""),
        "promotion_ready": ready,
        "reasons": reasons,
    }


def _capture_promotion_ready(corpus: dict[str, Any], capture: dict[str, Any]) -> bool:
    provenance = corpus.get("provenance") if isinstance(corpus.get("provenance"), dict) else {}
    endpoint_build = corpus.get("endpoint_build") if isinstance(corpus.get("endpoint_build"), dict) else {}
    drift_baseline = corpus.get("drift_baseline") if isinstance(corpus.get("drift_baseline"), dict) else {}
    expected = capture.get("expected") if isinstance(capture.get("expected"), dict) else {}
    review = capture.get("review") if isinstance(capture.get("review"), dict) else {}
    promotion = str(expected.get("promotion") or "retain")
    if promotion not in {"promote", "block"}:
        return False
    if str(provenance.get("data_origin") or "") == "synthetic":
        return False
    if _missing_required_keys(provenance, _PROVENANCE_REQUIRED_KEYS):
        return False
    if _missing_required_keys(endpoint_build, _ENDPOINT_BUILD_REQUIRED_KEYS):
        return False
    if _missing_required_keys(drift_baseline, _DRIFT_BASELINE_REQUIRED_KEYS):
        return False
    if _endpoint_contains_unknown(endpoint_build):
        return False
    return _review_approves_promotion(provenance, review, promotion)


def _review_approves_promotion(provenance: dict[str, Any], review: dict[str, Any], promotion: str) -> bool:
    corpus_status = str(provenance.get("review_status") or "")
    review_status = str(review.get("status") or "")
    decision = str(review.get("promotion_decision") or "")
    corpus_allows = corpus_status in {"operator_reviewed", "promotion_approved"}
    capture_allows = review_status in {"operator_reviewed", "promotion_approved"} and decision == promotion
    return corpus_allows and capture_allows


def _capture_review_reasons(corpus: dict[str, Any], capture: dict[str, Any], *, promotion_ready: bool) -> list[str]:
    provenance = corpus.get("provenance") if isinstance(corpus.get("provenance"), dict) else {}
    endpoint_build = corpus.get("endpoint_build") if isinstance(corpus.get("endpoint_build"), dict) else {}
    drift_baseline = corpus.get("drift_baseline") if isinstance(corpus.get("drift_baseline"), dict) else {}
    expected = capture.get("expected") if isinstance(capture.get("expected"), dict) else {}
    review = capture.get("review") if isinstance(capture.get("review"), dict) else {}
    promotion = str(expected.get("promotion") or "retain")
    if promotion not in {"promote", "block"}:
        return ["No promotion or blocking hint is present for this capture."]
    if promotion_ready:
        return ["Promotion or blocking hint is approved by non-synthetic provenance and capture-level review."]
    reasons: list[str] = []
    if str(provenance.get("data_origin") or "") == "synthetic":
        reasons.append("Synthetic fixture captures are not real lab promotion evidence.")
    if _missing_required_keys(provenance, _PROVENANCE_REQUIRED_KEYS):
        reasons.append("Required provenance fields are missing.")
    if _missing_required_keys(endpoint_build, _ENDPOINT_BUILD_REQUIRED_KEYS):
        reasons.append("Endpoint build metadata is incomplete.")
    if _missing_required_keys(drift_baseline, _DRIFT_BASELINE_REQUIRED_KEYS):
        reasons.append("Drift baseline metadata is incomplete.")
    if _endpoint_contains_unknown(endpoint_build):
        reasons.append("Endpoint build metadata contains unknown values.")
    if not _review_approves_promotion(provenance, review, promotion):
        reasons.append("Capture review does not explicitly approve this promotion or blocking decision.")
    return _dedupe_strings(reasons)


def _missing_required_keys(data: dict[str, Any], required: set[str]) -> list[str]:
    missing: list[str] = []
    for key in sorted(required):
        value = data.get(key)
        if value in ("", None, []):
            missing.append(key)
    return missing


def _endpoint_contains_unknown(endpoint_build: dict[str, Any]) -> bool:
    for key in sorted(_ENDPOINT_BUILD_REQUIRED_KEYS):
        value = str(endpoint_build.get(key) or "").strip().lower()
        if value in {"", "unknown", "unknown-fixture"}:
            return True
    return False


def _corpus_label(metadata: dict[str, Any]) -> str:
    return str(metadata.get("label") or metadata.get("source_path") or "corpus")


def _first_finding_for_family(result: ScanResult, family: str) -> Finding | None:
    for finding in result.findings:
        if target_family_for_finding(finding) == family:
            return finding
    return None


def _profile_match_from_signature(signature: dict[str, Any]) -> dict[str, Any]:
    stable_keys = [
        "response_classification",
        "http_auth_status",
        "ldap_result_code",
        "ldap_diagnostic_contains_80090346",
        "tds_prelogin_encryption",
        "tds_wrapped_tls",
        "tls_certificate_observed",
        "cbt_hash_observed",
    ]
    match = {
        key: signature[key]
        for key in stable_keys
        if key in signature
    }
    keywords = signature.get("response_keywords")
    if keywords:
        match["response_keywords"] = {"any_contains": sorted(str(item) for item in keywords)}
    errors = signature.get("mssql_errors")
    if errors:
        terms = _stable_mssql_error_terms(errors)
        if terms:
            match["mssql_errors"] = {"any_contains": terms}
    return match


def signature_id(signature: dict[str, Any], *, policy_state: str = "", finding_ref: str = "") -> str:
    payload = {
        "policy_state": policy_state,
        "finding_ref": finding_ref,
        "signature": _stable_signature_payload(signature),
    }
    digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return "sig-" + digest[:16]


def _stable_signature_payload(signature: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in sorted(signature.items())
        if key not in {"host", "port"} and value not in ("", None, [])
    }


def _capture_ref(capture: dict[str, Any], *, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "corpus": str(metadata.get("label") or metadata.get("source_path") or "corpus"),
        "finding_ref": str(capture.get("finding_ref") or ""),
        "signature_id": str(capture.get("signature_id") or ""),
        "policy_state": str((capture.get("expected") or {}).get("policy_state") or metadata.get("policy_state") or "observed"),
        "host": str(capture.get("host") or ""),
        "port": int(capture.get("port") or 0),
        "protocol": str(capture.get("protocol") or ""),
    }


def _capture_policy_state(capture: dict[str, Any], metadata: dict[str, Any]) -> str:
    return str((capture.get("expected") or {}).get("policy_state") or metadata.get("policy_state") or "observed")


def _missing_signature_keys(capture: dict[str, Any], required_keys: list[str]) -> list[str]:
    signature = capture.get("observed_signature") or {}
    return [key for key in required_keys if key not in signature]


def _capture_metadata_for(capture: dict[str, Any], corpuses: list[dict[str, Any]]) -> dict[str, Any]:
    for corpus in corpuses:
        for row in corpus.get("captures", []):
            if row is capture:
                return corpus.get("metadata", {})
    return {}


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value in ("", None):
        return []
    return [str(value).strip()]


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    rows: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            rows.append(text)
            seen.add(text)
    return rows


def _signature_group_key(capture: dict[str, Any]) -> str:
    signature = dict(capture.get("observed_signature") or {})
    match = _profile_match_from_signature(signature)
    expected = capture.get("expected") or {}
    payload = {
        "target_family": capture.get("target_family"),
        "match": match,
        "calibrated_state": expected.get("calibrated_state") or expected.get("classification"),
        "promotion": expected.get("promotion") or "retain",
    }
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _stability_row(
    requirement: dict[str, Any],
    captures: list[dict[str, Any]],
    *,
    metadata_by_capture: dict[int, dict[str, Any]],
    min_captures: int,
    stable_threshold: float,
) -> dict[str, Any]:
    signature_counts: Counter[str] = Counter()
    signature_payloads: dict[str, dict[str, Any]] = {}
    missing_signature_keys: set[str] = set()
    required_keys = list(requirement.get("required_signature_keys", []))
    for capture in captures:
        signature = dict(capture.get("observed_signature") or {})
        repeat_id = _repeat_signature_id(signature, policy_state=str(requirement["policy_state"]))
        signature_counts[repeat_id] += 1
        signature_payloads.setdefault(repeat_id, _stable_signature_payload(signature))
        missing_signature_keys.update(_missing_signature_keys(capture, required_keys))

    capture_count = len(captures)
    dominant_signature_id = ""
    dominant_count = 0
    if signature_counts:
        dominant_signature_id, dominant_count = signature_counts.most_common(1)[0]
    consistency_score = round(dominant_count / capture_count, 4) if capture_count else 0.0
    drift_keys = _drift_keys([signature_payloads[key] for key in signature_counts])
    drift_detected = bool(drift_keys) or (capture_count > 0 and consistency_score < stable_threshold)
    status = "stable"
    if not capture_count:
        status = "missing"
    elif capture_count < min_captures:
        status = "insufficient"
    elif drift_detected:
        status = "drift"
    promotion_counts = Counter(str((capture.get("expected") or {}).get("promotion") or "retain") for capture in captures)
    confidence_counts = Counter(str(capture.get("confidence") or "unknown") for capture in captures)
    recommended, downgrade_reasons = _recommended_stability_promotion(
        requirement,
        promotion_counts=promotion_counts,
        status=status,
        drift_detected=drift_detected,
        missing_signature_keys=sorted(missing_signature_keys),
        capture_count=capture_count,
        min_captures=min_captures,
        consistency_score=consistency_score,
        stable_threshold=stable_threshold,
    )
    return {
        "id": requirement["id"],
        "target_family": requirement["target_family"],
        "policy_state": requirement["policy_state"],
        "required": bool(requirement.get("required", True)),
        "status": status,
        "capture_count": capture_count,
        "min_captures": min_captures,
        "stable_threshold": stable_threshold,
        "consistency_score": consistency_score,
        "drift_detected": drift_detected,
        "drift_keys": drift_keys,
        "distinct_signature_count": len(signature_counts),
        "dominant_signature_id": dominant_signature_id,
        "dominant_signature": signature_payloads.get(dominant_signature_id, {}),
        "signature_ids": sorted(signature_counts),
        "signature_counts": dict(sorted(signature_counts.items())),
        "missing_signature_keys": sorted(missing_signature_keys),
        "capture_refs": [
            _capture_ref(capture, metadata=metadata_by_capture.get(id(capture), {}))
            for capture in captures
        ],
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "promotion_counts": dict(sorted(promotion_counts.items())),
        "promotion_expectation": requirement.get("promotion_expectation", ""),
        "recommended_profile_promotion": recommended,
        "promotion_downgrade_reasons": downgrade_reasons,
        "why": requirement.get("why", ""),
        "remaining_uncertainty": list(requirement.get("remaining_uncertainty", [])),
    }


def _lab_differential_pairs(requirements: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for requirement in requirements:
        grouped.setdefault(str(requirement.get("target_family") or ""), []).append(requirement)
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for family in sorted(grouped):
        rows = grouped[family]
        for left_index, left in enumerate(rows):
            for right in rows[left_index + 1:]:
                pairs.append((left, right))
    return pairs


def _matched_pair_filters(filters: list[str], family: str, left_state: str, right_state: str) -> set[str]:
    candidates = {
        f"{left_state}:{right_state}",
        f"{left_state}->{right_state}",
        f"{family}/{left_state}:{right_state}",
        f"{family}/{left_state}->{right_state}",
    }
    reverse_candidates = {
        f"{right_state}:{left_state}",
        f"{right_state}->{left_state}",
        f"{family}/{right_state}:{left_state}",
        f"{family}/{right_state}->{left_state}",
    }
    normalized = {item.strip().lower() for item in filters if str(item).strip()}
    return (candidates | reverse_candidates) & normalized


def _missing_differential_state(requirement: dict[str, Any], min_captures: int, stable_threshold: float) -> dict[str, Any]:
    return {
        "id": requirement["id"],
        "target_family": requirement["target_family"],
        "policy_state": requirement["policy_state"],
        "required": bool(requirement.get("required", True)),
        "status": "missing",
        "capture_count": 0,
        "min_captures": min_captures,
        "stable_threshold": stable_threshold,
        "consistency_score": 0.0,
        "drift_detected": False,
        "drift_keys": [],
        "distinct_signature_count": 0,
        "dominant_signature_id": "",
        "dominant_signature": {},
        "missing_signature_keys": list(requirement.get("required_signature_keys", [])),
        "promotion_expectation": requirement.get("promotion_expectation", ""),
        "recommended_profile_promotion": "unavailable",
        "promotion_downgrade_reasons": ["No captures exist for this required policy state."],
        "remaining_uncertainty": list(requirement.get("remaining_uncertainty", [])),
    }


def _lab_differential_row(
    left_req: dict[str, Any],
    right_req: dict[str, Any],
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    left_signature = dict(left.get("dominant_signature") or {})
    right_signature = dict(right.get("dominant_signature") or {})
    changed = _signature_differences(left_signature, right_signature)
    discriminator_keys = sorted(
        key
        for key in changed
        if key in _RESPONSE_DIFFERENTIAL_KEYS and key not in _CONTEXT_ONLY_SIGNATURE_KEYS
    )
    context_only_keys = sorted(key for key in changed if key not in discriminator_keys)
    left_status = str(left.get("status") or "missing")
    right_status = str(right.get("status") or "missing")
    if left_status == "missing" or right_status == "missing":
        status = "missing"
    elif left_status == "insufficient" or right_status == "insufficient":
        status = "insufficient"
    elif left_status != "stable" or right_status != "stable":
        status = "unstable"
    elif not changed:
        status = "indistinguishable"
    elif discriminator_keys:
        status = "differential"
    else:
        status = "context_only"
    promotion_support = _promotion_support(status, discriminator_keys)
    expected_relevant = _promotion_expectation_relevant(left_req) or _promotion_expectation_relevant(right_req)
    promotable = bool(
        status == "differential"
        and promotion_support in {"strong", "moderate"}
        and (_promotion_expectation_relevant(right_req) or right.get("recommended_profile_promotion") in {"promote", "block"})
    )
    reasons = _lab_differential_reasons(
        status,
        left=left,
        right=right,
        discriminator_keys=discriminator_keys,
        context_only_keys=context_only_keys,
        promotion_support=promotion_support,
        expected_relevant=expected_relevant,
        promotable=promotable,
    )
    return {
        "id": f"DIFF-{left_req['id']}-{right_req['id']}",
        "target_family": left_req["target_family"],
        "left_policy_state": left_req["policy_state"],
        "right_policy_state": right_req["policy_state"],
        "status": status,
        "left_status": left_status,
        "right_status": right_status,
        "left_signature_id": left.get("dominant_signature_id", ""),
        "right_signature_id": right.get("dominant_signature_id", ""),
        "left_capture_count": int(left.get("capture_count") or 0),
        "right_capture_count": int(right.get("capture_count") or 0),
        "changed_keys": changed,
        "discriminator_keys": discriminator_keys,
        "context_only_keys": context_only_keys,
        "promotion_support": promotion_support,
        "expected_promotion_relevant": expected_relevant,
        "promotable_candidate": promotable,
        "left_promotion_expectation": left_req.get("promotion_expectation", ""),
        "right_promotion_expectation": right_req.get("promotion_expectation", ""),
        "left_recommended_profile_promotion": left.get("recommended_profile_promotion", ""),
        "right_recommended_profile_promotion": right.get("recommended_profile_promotion", ""),
        "reasons": reasons,
        "remaining_uncertainty": _dedupe_strings(
            list(left_req.get("remaining_uncertainty", []))
            + list(right_req.get("remaining_uncertainty", []))
            + list(left.get("promotion_downgrade_reasons", []))
            + list(right.get("promotion_downgrade_reasons", []))
        ),
    }


def _signature_differences(left: dict[str, Any], right: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = sorted(set(left) | set(right))
    return {
        key: {"left": left.get(key), "right": right.get(key)}
        for key in keys
        if left.get(key) != right.get(key)
    }


def _promotion_expectation_relevant(requirement: dict[str, Any]) -> bool:
    expectation = str(requirement.get("promotion_expectation") or "")
    return expectation.startswith("promote_") or expectation.startswith("block_")


def _promotion_support(status: str, discriminator_keys: list[str]) -> str:
    if status != "differential":
        return "none"
    strong_keys = {
        "response_classification",
        "response_subclassification",
        "policy_inference",
        "oracle_signature",
        "ldap_result_code",
        "ldap_diagnostic_contains_80090346",
        "mssql_errors",
        "mssql_loginack",
        "response_keywords",
    }
    moderate_keys = {
        "http_auth_status",
        "tds_prelogin_encryption",
        "tds_wrapped_tls",
        "tls_certificate_observed",
        "cbt_hash_observed",
    }
    keys = set(discriminator_keys)
    if keys & strong_keys:
        return "strong"
    if keys & moderate_keys:
        return "moderate"
    return "weak"


def _lab_differential_reasons(
    status: str,
    *,
    left: dict[str, Any],
    right: dict[str, Any],
    discriminator_keys: list[str],
    context_only_keys: list[str],
    promotion_support: str,
    expected_relevant: bool,
    promotable: bool,
) -> list[str]:
    if status == "missing":
        return ["One or both policy states are missing from the lab corpus."]
    if status == "insufficient":
        return ["One or both policy states do not meet the repeated-capture requirement."]
    if status == "unstable":
        return ["One or both policy states are unstable; inspect drift keys before using the differential."]
    if status == "indistinguishable":
        reason = "Dominant signatures are indistinguishable across these policy states."
        if expected_relevant:
            reason += " This blocks promotion from this pair until stronger discriminators are captured."
        return [reason]
    if status == "context_only":
        return [
            "The signatures differ only on context fields; RelayX will not treat that as policy proof.",
            f"Context-only keys: {', '.join(context_only_keys)}.",
        ]
    reasons = [
        f"Stable response discriminator keys changed: {', '.join(discriminator_keys)}.",
        f"Promotion support is {promotion_support}.",
    ]
    if promotable:
        reasons.append("The candidate policy state is promotion-relevant and the differential is stable.")
    else:
        reasons.append("Review the pair before promotion; the differential may be useful but is not enough by itself.")
    if left.get("drift_keys") or right.get("drift_keys"):
        reasons.append("Historical drift keys are present in the source stability rows.")
    return reasons


def _recommended_stability_promotion(
    requirement: dict[str, Any],
    *,
    promotion_counts: Counter[str],
    status: str,
    drift_detected: bool,
    missing_signature_keys: list[str],
    capture_count: int,
    min_captures: int,
    consistency_score: float,
    stable_threshold: float,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    has_promote_hint = promotion_counts.get("promote", 0) > 0
    has_block_hint = promotion_counts.get("block", 0) > 0
    expectation = str(requirement.get("promotion_expectation") or "")
    expectation_promotable = expectation.startswith("promote_")
    expectation_blocking = expectation.startswith("block_")
    needs_promotion_review = has_promote_hint or has_block_hint or expectation_promotable or expectation_blocking
    if status == "missing":
        if needs_promotion_review:
            reasons.append("No captures exist for this required policy state.")
        return "unavailable", reasons
    if needs_promotion_review and capture_count < min_captures:
        reasons.append(f"capture_count={capture_count} is below min_captures={min_captures}.")
    if needs_promotion_review and missing_signature_keys:
        reasons.append("Required signature keys are missing: " + ", ".join(missing_signature_keys) + ".")
    if needs_promotion_review and drift_detected:
        reasons.append(
            f"repeat-capture consistency_score={consistency_score} is below the stability requirement {stable_threshold}, or signature drift was observed."
        )
    if expectation_blocking and status == "stable" and not missing_signature_keys and capture_count >= min_captures:
        return "block", reasons
    if has_block_hint and not expectation_blocking:
        reasons.append(f"Capture hints include block but matrix expectation is {expectation or 'review'}.")
    if has_promote_hint and not expectation_promotable:
        reasons.append(f"Capture hints include promote but matrix expectation is {expectation or 'review'}.")
    if (
        has_promote_hint
        and expectation_promotable
        and status == "stable"
        and not missing_signature_keys
        and capture_count >= min_captures
    ):
        return "promote", reasons
    if (expectation_promotable or expectation_blocking) and not has_promote_hint and not has_block_hint:
        reasons.append("Captures do not include a promote or block hint.")
    return "retain", reasons


def _repeat_signature_id(signature: dict[str, Any], *, policy_state: str) -> str:
    payload = {
        "policy_state": policy_state,
        "signature": _stable_signature_payload(signature),
    }
    digest = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return "stable-sig-" + digest[:16]


def _drift_keys(signatures: list[dict[str, Any]]) -> list[str]:
    values_by_key: dict[str, set[str]] = {}
    all_keys = set().union(*(row.keys() for row in signatures)) if signatures else set()
    for signature in signatures:
        for key in all_keys:
            values_by_key.setdefault(key, set()).add(_canonical_value(signature.get(key)))
    return sorted(key for key, values in values_by_key.items() if len(values) > 1)


def _canonical_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _bounded_threshold(value: float) -> float:
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        threshold = 0.85
    return min(1.0, max(0.0, round(threshold, 4)))


def _render_counts(values: dict[str, int]) -> str:
    if not values:
        return "-"
    return ", ".join(f"{key}={value}" for key, value in sorted(values.items()))


def _stable_mssql_error_terms(errors: Any) -> list[str]:
    rows = errors if isinstance(errors, list) else [errors]
    terms: set[str] = set()
    for row in rows:
        lowered = str(row).lower()
        if "login failed" in lowered:
            terms.add("login failed")
        if "invalid credentials" in lowered:
            terms.add("invalid credentials")
        if "channel binding" in lowered:
            terms.add("channel binding")
        if "extended protection" in lowered:
            terms.add("extended protection")
        if "bad bindings" in lowered or "80090346" in lowered:
            terms.add("bad bindings")
    return sorted(terms)


def _unique_state_name(raw: str, seen: set[str]) -> str:
    base = "".join(ch if ch.isalnum() else "_" for ch in raw.strip().lower()).strip("_") or "observed"
    name = base
    index = 2
    while name in seen:
        name = f"{base}_{index}"
        index += 1
    seen.add(name)
    return name
