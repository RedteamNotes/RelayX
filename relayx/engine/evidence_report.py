from __future__ import annotations

from collections import Counter
from typing import Any

from .. import __version__
from ..models import Evidence, Finding, RelayPath, ScanResult, Status
from .calibration import target_family_for_finding


_PROTOCOL_JUDGEMENT_FAMILIES = {
    "http_iis_epa",
    "adcs_web_enrollment",
    "winrm_ntlm",
    "ldap_signing",
    "ldaps_cbt",
    "mssql_epa",
}

_PROTOCOL_JUDGEMENT_KEYS = {
    "relayx_response_classification": "response_classification",
    "relayx_policy_inference": "policy_inference",
    "relayx_remaining_uncertainty": "remaining_uncertainty",
}

_SOURCE_CATEGORIES = {
    "wire_observation": "Evidence observed from protocol negotiation, transport, TLS, bind/login, or service response material.",
    "policy_inference": "RelayX protocol-oracle interpretation, including response class, policy inference, oracle signature, and uncertainty boundary.",
    "lab_calibration": "Evidence produced by lab calibration, baseline comparison, or generated profile promotion logic.",
    "source_model": "Modeled source capability or source metadata used for path construction.",
    "route_model": "Modeled route, pivot, reachability, hop, or route-risk metadata.",
    "control_mapping": "RelayX rule, hardening gate, defensive control, remediation, or decision-calculus mapping.",
    "operator_context": "Operator-supplied validation/execution context, OPSEC policy context, audit scope, or adapter lifecycle context.",
    "error": "Error evidence emitted by a scanner, oracle, validator, or adapter.",
    "unsupported": "Explicit unsupported capability or unsupported execution boundary.",
    "model_inference": "General inferred evidence that does not fit a more specific category.",
    "other_observation": "Observed evidence that does not fit the protocol wire-observation taxonomy yet.",
}

_WIRE_OBSERVATION_KEYS = {
    "smb_signing_required",
    "smb_security_mode",
    "http_status",
    "www_authenticate",
    "ntlm_type2_challenge",
    "ntlm_authenticate_validation",
    "ldap_reachable",
    "ldaps_reachable",
    "rootdse_supported_sasl_mechanisms",
    "ldap_sasl_ntlm_type2_challenge",
    "ldap_ntlm_authenticate_validation",
    "ldap_bind_result_code",
    "tls_certificate_sha256",
    "tds_prelogin_encryption",
    "tds_wrapped_tls",
    "mssql_cbt_tls_server_end_point",
    "mssql_sspi_ntlm_type2_challenge",
    "mssql_ntlm_authenticate_validation",
    "tds_loginack_observed",
    "tds_errors",
}
_WIRE_PREFIXES = ("http_", "ldap_", "ldaps_", "mssql_", "tds_", "tls_", "smb_", "ntlm_")
_POLICY_PREFIXES = ("relayx_response_", "relayx_policy_", "relayx_oracle_", "relayx_remaining_")
_SOURCE_PREFIXES = ("source_",)
_ROUTE_PREFIXES = ("route_",)
_CONTROL_KEYS = {
    "relayx_controls",
    "relayx_rule_id",
    "relayx_decision",
    "relayx_target_family",
    "relayx_preconditions",
    "relayx_hardening_gates",
}
_OPERATOR_PREFIXES = ("opsec_", "validation_", "execution_", "adapter_", "audit_", "scope_", "operator_")


def build_evidence_report(result: ScanResult) -> dict[str, Any]:
    finding_rows = [
        _finding_row(finding, index)
        for index, finding in enumerate(result.findings, start=1)
    ]
    path_rows = [
        _path_row(path)
        for path in result.paths
    ]
    records = finding_rows + path_rows
    required_records = [row for row in records if row["protocol_judgement_required"]]
    warning_records = [row for row in records if row["status"] == "warn"]
    fail_records = [row for row in records if row["status"] == "fail"]
    source_category_counts = Counter()
    judgement_role_counts = Counter()
    for row in records:
        source_category_counts.update(row.get("source_category_counts", {}))
        judgement_role_counts.update(row.get("judgement_role_counts", {}))
    status = "pass"
    if fail_records:
        status = "fail"
    elif warning_records:
        status = "warn"
    return {
        "name": "RelayX evidence report",
        "version": 1,
        "schema_version": 1,
        "tool": "RelayX",
        "tool_version": __version__,
        "result_version": result.metadata.version,
        "status": status,
        "summary": {
            "findings": len(finding_rows),
            "paths": len(path_rows),
            "records": len(records),
            "complete": sum(1 for row in records if row["status"] == "pass"),
            "warning": len(warning_records),
            "failed": len(fail_records),
            "protocol_judgement_required": len(required_records),
            "protocol_judgement_complete": sum(
                1
                for row in required_records
                if not row["missing_contract_keys"]
            ),
            "missing_evidence": sum(1 for row in records if "evidence" in row["missing_contract_keys"]),
            "missing_policy_inference": sum(1 for row in records if "policy_inference" in row["missing_contract_keys"]),
            "missing_remaining_uncertainty": sum(1 for row in records if "remaining_uncertainty" in row["missing_contract_keys"]),
            "unknown_confidence": sum(1 for row in records if row["unknown_confidence_evidence"] > 0),
            "source_categories": dict(sorted(source_category_counts.items())),
            "judgement_roles": dict(sorted(judgement_role_counts.items())),
            "taxonomy_generic": source_category_counts.get("model_inference", 0) + source_category_counts.get("other_observation", 0),
        },
        "records": records,
        "confidence_contract": {
            "version": 1,
            "evidence_model": "result_evidence_completeness",
            "status_rule": "fail when candidate or relayable records have no evidence; warn when protocol judgement records miss policy inference, uncertainty, or contain unknown-confidence evidence.",
            "protocol_judgement_keys": sorted(_PROTOCOL_JUDGEMENT_KEYS),
            "source_taxonomy_version": 1,
            "source_categories": dict(sorted(_SOURCE_CATEGORIES.items())),
            "scope": "Offline audit of an existing RelayX result; does not scan, validate, relay, or modify the result.",
            "remaining_uncertainty": [
                "This report checks evidence shape and judgement completeness; it does not prove the correctness of a protocol oracle.",
                "Findings promoted by lab calibration should still be reviewed against the lab profile and baseline differential evidence.",
            ],
        },
    }


def render_evidence_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "RelayX Evidence Report",
        "",
        f"Status       : {report['status']}",
        f"Records      : {summary['records']} ({summary['findings']} findings, {summary['paths']} paths)",
        f"Complete     : {summary['complete']}",
        f"Issues       : {summary['warning']} warning, {summary['failed']} failed",
        f"Judgements   : {summary['protocol_judgement_complete']}/{summary['protocol_judgement_required']} protocol records complete",
        f"Missing      : evidence={summary['missing_evidence']} policy_inference={summary['missing_policy_inference']} uncertainty={summary['missing_remaining_uncertainty']}",
        f"Unknown conf : {summary['unknown_confidence']}",
        f"Sources      : {_render_counts(summary.get('source_categories', {}))}",
        "",
        "Records:",
    ]
    for row in report.get("records", []):
        lines.append(
            f"  - {row['status']}: {row['id']} {row['target_family']} "
            f"evidence={row['evidence_count']} confidence={row['record_confidence']}"
        )
        if row.get("policy_inference"):
            lines.append(f"    policy_inference: {row['policy_inference']}")
        if row.get("response_classification"):
            lines.append(f"    response: {row['response_classification']} / {row.get('response_subclassification') or '-'}")
        if row.get("source_category_counts"):
            lines.append(f"    sources: {_render_counts(row['source_category_counts'])}")
        if row.get("missing_contract_keys"):
            lines.append(f"    missing: {', '.join(row['missing_contract_keys'])}")
        if row.get("remaining_uncertainty"):
            lines.append(f"    uncertainty: {'; '.join(row['remaining_uncertainty'])}")
        for reason in row.get("reasons", []):
            lines.append(f"    why: {reason}")
    return "\n".join(lines)


def evidence_report_to_json(report: dict[str, Any]) -> str:
    import json

    return json.dumps(report, indent=2, sort_keys=True)


def _finding_row(finding: Finding, index: int) -> dict[str, Any]:
    family = target_family_for_finding(finding)
    return _record_row(
        record_id=f"F-{index:04d}",
        kind="finding",
        target=finding.host,
        service=f"{finding.protocol}/{finding.port}",
        status=finding.status.value,
        record_confidence=finding.confidence.value,
        target_family=family,
        evidence=finding.evidence,
    )


def _path_row(path: RelayPath) -> dict[str, Any]:
    return _record_row(
        record_id=path.id,
        kind="path",
        target=path.target,
        service=path.target_service,
        status=path.status.value,
        record_confidence=path.confidence.value,
        target_family=_target_family_for_path(path),
        evidence=path.evidence,
    )


def _record_row(
    *,
    record_id: str,
    kind: str,
    target: str,
    service: str,
    status: str,
    record_confidence: str,
    target_family: str,
    evidence: list[Evidence],
) -> dict[str, Any]:
    evidence_by_key = {item.key: item for item in evidence}
    evidence_count = len(evidence)
    type_counts = Counter(item.type.value for item in evidence)
    confidence_counts = Counter(item.confidence.value for item in evidence)
    evidence_sources = [_evidence_source(item) for item in evidence]
    source_category_counts = Counter(row["source_category"] for row in evidence_sources)
    judgement_role_counts = Counter(row["judgement_role"] for row in evidence_sources)
    protocol_required = target_family in _PROTOCOL_JUDGEMENT_FAMILIES and status in {
        Status.CANDIDATE.value,
        Status.RELAYABLE.value,
    }
    missing: list[str] = []
    reasons: list[str] = []
    if status in {Status.CANDIDATE.value, Status.RELAYABLE.value} and evidence_count == 0:
        missing.append("evidence")
        reasons.append("Candidate or relayable records must carry evidence.")
    if protocol_required:
        for evidence_key, contract_key in _PROTOCOL_JUDGEMENT_KEYS.items():
            if evidence_key not in evidence_by_key:
                missing.append(contract_key)
        if missing:
            reasons.append("Protocol judgement records should expose classification, policy inference, and remaining uncertainty.")
    unknown_confidence = confidence_counts.get("unknown", 0)
    if unknown_confidence:
        reasons.append("One or more evidence records have unknown confidence.")
    row_status = "pass"
    if "evidence" in missing:
        row_status = "fail"
    elif missing or unknown_confidence:
        row_status = "warn"
    return {
        "id": record_id,
        "kind": kind,
        "target": target,
        "service": service,
        "target_family": target_family,
        "record_status": status,
        "record_confidence": record_confidence,
        "status": row_status,
        "protocol_judgement_required": protocol_required,
        "evidence_count": evidence_count,
        "evidence_keys": sorted(evidence_by_key),
        "evidence_type_counts": dict(sorted(type_counts.items())),
        "evidence_confidence_counts": dict(sorted(confidence_counts.items())),
        "source_category_counts": dict(sorted(source_category_counts.items())),
        "judgement_role_counts": dict(sorted(judgement_role_counts.items())),
        "evidence_sources": evidence_sources,
        "unknown_confidence_evidence": unknown_confidence,
        "response_classification": _evidence_value(evidence_by_key, "relayx_response_classification", ""),
        "response_subclassification": _evidence_value(evidence_by_key, "relayx_response_subclassification", ""),
        "policy_inference": _evidence_value(evidence_by_key, "relayx_policy_inference", ""),
        "oracle_signature": _evidence_value(evidence_by_key, "relayx_oracle_signature", ""),
        "remaining_uncertainty": _list_value(_evidence_value(evidence_by_key, "relayx_remaining_uncertainty", [])),
        "missing_contract_keys": sorted(set(missing)),
        "reasons": reasons,
    }


def _target_family_for_path(path: RelayPath) -> str:
    service = path.target_service.lower()
    transport = path.transport.lower()
    if "/certsrv" in service:
        return "adcs_web_enrollment"
    if "/wsman" in service:
        return "winrm_ntlm"
    if "http" in transport or service.startswith(("http/", "https/")):
        return "http_iis_epa"
    if service.startswith("ldap/") or transport == "ldap":
        return "ldap_signing"
    if service.startswith("ldaps/") or transport == "ldaps":
        return "ldaps_cbt"
    if "mssql" in transport or service.startswith("mssql/"):
        return "mssql_epa"
    if service.startswith("smb/") or transport == "smb":
        return "smb_signing"
    return transport or service


def _evidence_source(item: Evidence) -> dict[str, Any]:
    category = _source_category(item)
    return {
        "key": item.key,
        "type": item.type.value,
        "confidence": item.confidence.value,
        "source_category": category,
        "judgement_role": _judgement_role(item.key, category),
        "detail": item.detail,
    }


def _source_category(item: Evidence) -> str:
    key = item.key
    if item.type.value == "error" or key.endswith("_error") or "error" in key:
        return "error"
    if item.type.value == "unsupported":
        return "unsupported"
    if "lab" in key or "calibration" in key or "baseline" in key:
        return "lab_calibration"
    if key.startswith(_POLICY_PREFIXES):
        return "policy_inference"
    if key.startswith(_SOURCE_PREFIXES):
        return "source_model"
    if key.startswith(_ROUTE_PREFIXES):
        return "route_model"
    if key in _CONTROL_KEYS:
        return "control_mapping"
    if key.startswith(_OPERATOR_PREFIXES):
        return "operator_context"
    if key in _WIRE_OBSERVATION_KEYS or key.startswith(_WIRE_PREFIXES):
        return "wire_observation"
    if item.type.value == "observed":
        return "other_observation"
    if item.type.value == "inferred":
        return "model_inference"
    return "model_inference"


def _judgement_role(key: str, category: str) -> str:
    if key == "relayx_remaining_uncertainty":
        return "uncertainty_boundary"
    if key == "relayx_policy_inference":
        return "policy_inference"
    if key.startswith("relayx_response_") or key == "relayx_oracle_signature":
        return "response_semantics"
    if category == "wire_observation":
        return "observation"
    if category == "lab_calibration":
        return "calibration_evidence"
    if category == "source_model":
        return "source_context"
    if category == "route_model":
        return "route_context"
    if category == "control_mapping":
        return "control_mapping"
    if category == "operator_context":
        return "operator_context"
    if category in {"error", "unsupported"}:
        return category
    return "supporting_context"


def _evidence_value(evidence_by_key: dict[str, Evidence], key: str, default: Any = None) -> Any:
    item = evidence_by_key.get(key)
    return item.value if item else default


def _list_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def _render_counts(counts: dict[str, Any]) -> str:
    if not counts:
        return "-"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
