from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Confidence, Evidence, EvidenceType, Impact, RelayPath, Status
from .evidence import evidence_value, upsert_evidence


@dataclass(slots=True)
class Gate:
    key: str
    state: str
    reason: str
    confidence: Confidence = Confidence.MEDIUM

    def as_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "state": self.state,
            "reason": self.reason,
            "confidence": self.confidence.value,
        }


@dataclass(slots=True)
class PathAssessment:
    rule_id: str
    target_family: str
    decision: str
    controls: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    gates: list[Gate] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "target_family": self.target_family,
            "decision": self.decision,
            "controls": self.controls,
            "preconditions": self.preconditions,
            "gates": [gate.as_dict() for gate in self.gates],
            "warnings": self.warnings,
        }


def annotate_paths(paths: list[RelayPath]) -> list[RelayPath]:
    for path in paths:
        assessment = assess_path(path)
        _apply_assessment(path, assessment)
    return paths


def assess_path(path: RelayPath) -> PathAssessment:
    target_family = _target_family(path)
    rule_id = _rule_id(path, target_family)
    gates = _hardening_gates(path, target_family)
    preconditions = _preconditions(path, target_family)
    controls = _controls(path, target_family)
    warnings = _warnings(path, target_family, gates)
    decision = _decision(path, gates)
    return PathAssessment(
        rule_id=rule_id,
        target_family=target_family,
        decision=decision,
        controls=controls,
        preconditions=preconditions,
        gates=gates,
        warnings=warnings,
    )


def _apply_assessment(path: RelayPath, assessment: PathAssessment) -> None:
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.INFERRED,
            "relayx_rule_id",
            assessment.rule_id,
            Confidence.MEDIUM,
            raw=assessment.as_dict(),
            detail="RelayX relay calculus rule applied to this path.",
        ),
    )
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.INFERRED,
            "relayx_target_family",
            assessment.target_family,
            Confidence.MEDIUM,
        ),
    )
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.INFERRED,
            "relayx_preconditions",
            assessment.preconditions,
            Confidence.MEDIUM,
        ),
    )
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.INFERRED,
            "relayx_hardening_gates",
            [gate.as_dict() for gate in assessment.gates],
            Confidence.MEDIUM,
            detail="Hardening gates derived from observed protocol evidence.",
        ),
    )
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.INFERRED,
            "relayx_decision",
            assessment.decision,
            Confidence.MEDIUM,
            raw=assessment.as_dict(),
        ),
    )
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.INFERRED,
            "relayx_controls",
            assessment.controls,
            Confidence.MEDIUM,
            detail="Defensive control families that reduce or remove this path.",
        ),
    )
    for warning in assessment.warnings:
        if warning not in path.blockers:
            path.blockers.append(warning)
    if assessment.decision == "blocked":
        path.status = Status.BLOCKED
        path.impact = Impact.INFO if path.impact == Impact.LOW else path.impact


def _target_family(path: RelayPath) -> str:
    service = path.target_service.lower()
    transport = path.transport.lower()
    if "/certsrv" in service:
        return "adcs_web_enrollment"
    if "/wsman" in service:
        return "winrm_ntlm"
    if service.startswith("smb/"):
        return "smb_unsigned"
    if service.startswith("ldaps/"):
        return "ldaps_channel_binding"
    if service.startswith("ldap/"):
        return "ldap_signing"
    if service.startswith("mssql/") or "mssql" in transport:
        return "mssql_epa"
    if service.startswith("https/") or service.startswith("http/"):
        return "http_ntlm"
    return "generic_ntlm"


def _rule_id(path: RelayPath, target_family: str) -> str:
    prefix = {
        "adcs_web_enrollment": "RX-ADCS-HTTP",
        "winrm_ntlm": "RX-WINRM-HTTP",
        "http_ntlm": "RX-HTTP-NTLM",
        "smb_unsigned": "RX-SMB-SIGNING",
        "ldap_signing": "RX-LDAP-SIGNING",
        "ldaps_channel_binding": "RX-LDAPS-CBT",
        "mssql_epa": "RX-MSSQL-EPA",
    }.get(target_family, "RX-GENERIC-NTLM")
    capability = str(evidence_value(path, "source_capability", "generic"))
    return f"{prefix}:{capability}"


def _hardening_gates(path: RelayPath, target_family: str) -> list[Gate]:
    gates: list[Gate] = []
    if target_family == "smb_unsigned":
        required = evidence_value(path, "smb_signing_required")
        gates.append(
            Gate(
                "smb_signing",
                "blocked" if required is True else "open" if required is False else "unknown",
                "SMB signing required" if required is True else "SMB signing is not required." if required is False else "SMB signing evidence is missing.",
                Confidence.HIGH if required in {True, False} else Confidence.LOW,
            )
        )
    if target_family in {"http_ntlm", "adcs_web_enrollment", "winrm_ntlm"}:
        _append_type2_gate(path, gates, "ntlm_type2_challenge", "HTTP NTLM Type2 challenge")
        _append_response_gate(path, gates, service="HTTP EPA/CBT")
    if target_family == "ldap_signing":
        _append_type2_gate(path, gates, "ldap_sasl_ntlm_type2_challenge", "LDAP SASL NTLM Type2 challenge")
        _append_response_gate(path, gates, service="LDAP signing")
    if target_family == "ldaps_channel_binding":
        _append_type2_gate(path, gates, "ldap_sasl_ntlm_type2_challenge", "LDAPS SASL NTLM Type2 challenge")
        tls_hash = bool(evidence_value(path, "tls_certificate_sha256", ""))
        gates.append(
            Gate(
                "tls_cbt_evidence",
                "open" if tls_hash else "unknown",
                "TLS certificate hash is available for CBT calculation." if tls_hash else "TLS certificate hash was not observed.",
                Confidence.MEDIUM if tls_hash else Confidence.LOW,
            )
        )
        _append_response_gate(path, gates, service="LDAPS CBT")
    if target_family == "mssql_epa":
        _append_type2_gate(path, gates, "mssql_sspi_ntlm_type2_challenge", "MSSQL SSPI NTLM Type2 challenge")
        tls = bool(evidence_value(path, "tds_wrapped_tls", False))
        gates.append(
            Gate(
                "tds_wrapped_tls",
                "open" if tls else "unknown",
                "TDS-wrapped TLS and CBT evidence were observed." if tls else "TDS-wrapped TLS CBT evidence was not observed.",
                Confidence.HIGH if tls else Confidence.LOW,
            )
        )
        _append_response_gate(path, gates, service="MSSQL EPA/CBT")
    return gates


def _append_type2_gate(path: RelayPath, gates: list[Gate], key: str, label: str) -> None:
    observed = bool(evidence_value(path, key, False))
    gates.append(
        Gate(
            key,
            "open" if observed else "unknown",
            f"{label} was observed." if observed else f"{label} was not observed.",
            Confidence.HIGH if observed else Confidence.LOW,
        )
    )


def _append_response_gate(path: RelayPath, gates: list[Gate], service: str) -> None:
    classification = str(evidence_value(path, "relayx_response_classification", "not_performed"))
    subclassification = str(evidence_value(path, "relayx_response_subclassification", ""))
    policy_inference = str(evidence_value(path, "relayx_policy_inference", ""))
    if classification in {"possible_cbt_enforcement", "possible_epa_cbt_enforcement", "stronger_auth_or_confidentiality_required"}:
        state = "uncertain"
        reason = _response_reason(
            f"{service} returned a hardening-related signal: {classification}.",
            subclassification,
            policy_inference,
        )
        confidence = Confidence.MEDIUM
    elif classification == "synthetic_auth_rejected":
        state = "open"
        reason = _response_reason(
            "Synthetic credentials were rejected; this is expected and not proof of enforcement.",
            subclassification,
            policy_inference,
        )
        confidence = Confidence.MEDIUM
    elif classification == "unexpected_acceptance":
        state = "critical_anomaly"
        reason = _response_reason(
            "Synthetic credentials appeared accepted; confirm lab/proxy behavior immediately.",
            subclassification,
            policy_inference,
        )
        confidence = Confidence.HIGH
    elif classification == "not_performed":
        state = "unknown"
        reason = _response_reason(
            "Authenticate-stage validation was not performed.",
            subclassification,
            policy_inference,
        )
        confidence = Confidence.LOW
    else:
        state = "unknown"
        reason = _response_reason(
            f"Response classification is inconclusive: {classification}.",
            subclassification,
            policy_inference,
        )
        confidence = Confidence.LOW
    gates.append(Gate("authenticate_response", state, reason, confidence))


def _response_reason(base: str, subclassification: str, policy_inference: str) -> str:
    parts = [base]
    if subclassification:
        parts.append(f"Subclassification: {subclassification}.")
    if policy_inference:
        parts.append(f"Policy inference: {policy_inference}.")
    return " ".join(parts)


def _preconditions(path: RelayPath, target_family: str) -> list[str]:
    preconditions = [
        "Written authorization and exact source/target scope are confirmed.",
        "A real NTLM source identity exists and is permitted for validation.",
        "Operator has a one-path validation plan and rollback owner.",
    ]
    if evidence_value(path, "source_capability"):
        preconditions.append("Source capability was supplied by asset inventory or operator profile.")
    else:
        preconditions.append("Source capability is generic and must be confirmed before validation.")
    if target_family in {"http_ntlm", "adcs_web_enrollment", "winrm_ntlm", "ldaps_channel_binding", "mssql_epa"}:
        preconditions.append("EPA/CBT policy state is calibrated or explicitly accepted as unknown.")
    if target_family in {"ldap_signing", "ldaps_channel_binding"}:
        preconditions.append("LDAP signing/channel-binding policy impact is understood before escalation.")
    if target_family == "mssql_epa":
        preconditions.append("SQL Server encryption and EPA behavior are validated in lab or maintenance window.")
    return preconditions


def _controls(path: RelayPath, target_family: str) -> list[str]:
    controls = {
        "ntlm_restriction",
        "credential_boundary",
    }
    source_capability = str(evidence_value(path, "source_capability", ""))
    if source_capability in {"webclient", "name_resolution"}:
        controls.add("outbound_auth_egress")
    if source_capability == "webclient":
        controls.add("webclient_hardening")
    if source_capability in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        controls.add("rpc_coercion_reduction")
    if source_capability == "mssql_outbound":
        controls.add("mssql_service_account_hardening")
    if source_capability == "name_resolution":
        controls.add("name_resolution_hardening")
    if target_family == "smb_unsigned":
        controls.add("smb_signing")
    if target_family == "ldap_signing":
        controls.add("ldap_signing")
    if target_family == "ldaps_channel_binding":
        controls.add("ldap_channel_binding")
    if target_family in {"http_ntlm", "adcs_web_enrollment", "winrm_ntlm"}:
        controls.add("http_epa")
    if target_family == "adcs_web_enrollment":
        controls.add("adcs_hardening")
    if target_family == "mssql_epa":
        controls.add("mssql_epa")
    return sorted(controls)


def _warnings(path: RelayPath, target_family: str, gates: list[Gate]) -> list[str]:
    warnings: list[str] = []
    for gate in gates:
        if gate.state == "blocked":
            warnings.append(gate.reason)
        elif gate.state == "uncertain":
            warnings.append(gate.reason)
        elif gate.state == "critical_anomaly":
            warnings.append(gate.reason)
    if target_family != "smb_unsigned" and evidence_value(path, "relayx_response_classification", "not_performed") == "not_performed":
        warnings.append("Authenticate-stage validation was not performed; relayability remains theoretical.")
    return warnings


def _decision(path: RelayPath, gates: list[Gate]) -> str:
    if path.status == Status.BLOCKED or any(gate.state == "blocked" for gate in gates):
        return "blocked"
    if any(gate.state == "critical_anomaly" for gate in gates):
        return "investigate_anomaly"
    if any(gate.state == "uncertain" for gate in gates):
        return "candidate_needs_calibration"
    if any(gate.state == "unknown" for gate in gates):
        return "candidate_needs_validation"
    return "candidate_ready"
