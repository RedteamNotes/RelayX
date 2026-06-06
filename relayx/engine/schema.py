from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..models import Confidence, EvidenceType, Impact, NoiseLevel, Status


SCHEMA_VERSION = 1
VALIDATION_REPORT_VERSION = 1

SchemaKind = str

SCHEMA_KINDS: tuple[SchemaKind, ...] = (
    "result",
    "evidence",
    "lab-profile",
    "lab-corpus",
    "lab-provenance",
    "lab-stability",
    "lab-differential",
    "evidence-report",
    "execution-record",
    "module-manifest",
    "opsec-policy",
    "route-report",
    "bundle-manifest",
    "quality-gate",
    "opengraph",
    "jsonl",
    "csv",
)

_STATUS_VALUES = {item.value for item in Status}
_CONFIDENCE_VALUES = {item.value for item in Confidence}
_EVIDENCE_TYPE_VALUES = {item.value for item in EvidenceType}
_IMPACT_VALUES = {item.value for item in Impact}
_NOISE_VALUES = {item.value for item in NoiseLevel}
_EXECUTION_MODES = {"dry-run", "armed", "confirmed"}
_GUARDRAIL_STATES = {"pass", "warn", "fail"}
_PROMOTION_VALUES = {"retain", "promote", "block"}
_LAB_STABILITY_STATUSES = {"stable", "missing", "insufficient", "drift"}
_LAB_STABILITY_RECOMMENDATIONS = {"retain", "promote", "block", "unavailable"}
_LAB_DIFFERENTIAL_STATUSES = {"differential", "context_only", "indistinguishable", "missing", "insufficient", "unstable"}
_LAB_PROMOTION_SUPPORT = {"none", "weak", "moderate", "strong"}
_LAB_PROVENANCE_STATUSES = {"pass", "warn", "fail"}
_LAB_CORPUS_KINDS = {"synthetic_fixture", "authorized_lab_capture", "external_lab_capture"}
_LAB_DATA_ORIGINS = {"synthetic", "operator_supplied", "real_lab", "external"}
_LAB_REVIEW_STATUSES = {
    "fixture_only",
    "pending_review",
    "operator_reviewed",
    "promotion_approved",
    "promotion_rejected",
    "not_for_promotion",
}
_LAB_PROMOTION_DECISIONS = {"pending", "retain", "promote", "block", "reject", "not_for_promotion"}
_EVIDENCE_SOURCE_CATEGORIES = {
    "wire_observation",
    "policy_inference",
    "lab_calibration",
    "source_model",
    "route_model",
    "control_mapping",
    "operator_context",
    "error",
    "unsupported",
    "model_inference",
    "other_observation",
}
_EVIDENCE_JUDGEMENT_ROLES = {
    "observation",
    "response_semantics",
    "policy_inference",
    "uncertainty_boundary",
    "calibration_evidence",
    "source_context",
    "route_context",
    "control_mapping",
    "operator_context",
    "error",
    "unsupported",
    "supporting_context",
}
_JSONL_EVENT_TYPES = {
    "relayx.scan",
    "relayx.source",
    "relayx.finding",
    "relayx.path",
    "relayx.control",
}
_ROUTE_STATES = {
    "direct",
    "routed",
    "metadata_only",
    "assumed_reachable",
    "unreachable",
    "source_out_of_scope",
    "target_out_of_scope",
}
_ROUTE_RISK_LEVELS = {"low", "medium", "high", "critical"}
_CSV_HEADER = [
    "record_type",
    "id",
    "host",
    "port",
    "protocol",
    "status",
    "score",
    "impact",
    "confidence",
    "source",
    "transport",
    "target",
    "target_service",
    "rule_id",
    "decision",
    "target_family",
    "source_capability",
    "control_keys",
    "control_labels",
    "route_state",
    "route_risk_level",
    "route_risk_score",
    "summary",
    "blockers",
    "fixes",
    "remaining_uncertainty",
    "field_contract_version",
]


@dataclass(slots=True)
class SchemaIssue:
    severity: str
    path: str
    message: str
    expected: str = ""
    actual: str = ""

    def as_dict(self) -> dict[str, str]:
        data = {
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
        }
        if self.expected:
            data["expected"] = self.expected
        if self.actual:
            data["actual"] = self.actual
        return data


@dataclass(slots=True)
class SchemaFileReport:
    path: str
    kind: str
    requested_kind: str
    valid: bool
    issues: list[SchemaIssue] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "requested_kind": self.requested_kind,
            "valid": self.valid,
            "issues": [issue.as_dict() for issue in self.issues],
        }


@dataclass(slots=True)
class SchemaValidationReport:
    path: str
    kind: str
    files: list[SchemaFileReport]

    @property
    def valid(self) -> bool:
        return all(file.valid for file in self.files)

    @property
    def summary(self) -> dict[str, int]:
        errors = sum(1 for file in self.files for issue in file.issues if issue.severity == "error")
        warnings = sum(1 for file in self.files for issue in file.issues if issue.severity == "warning")
        return {
            "files": len(self.files),
            "valid_files": sum(1 for file in self.files if file.valid),
            "invalid_files": sum(1 for file in self.files if not file.valid),
            "errors": errors,
            "warnings": warnings,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": "RelayX schema validation",
            "version": VALIDATION_REPORT_VERSION,
            "schema_version": SCHEMA_VERSION,
            "path": self.path,
            "kind": self.kind,
            "valid": self.valid,
            "summary": self.summary,
            "files": [file.as_dict() for file in self.files],
        }


def schema_contracts() -> dict[str, Any]:
    return {
        "name": "RelayX schema contracts",
        "version": 1,
        "schema_version": SCHEMA_VERSION,
        "kinds": [
            _contract(
                "result",
                "Primary RelayX assessment artifact.",
                ["metadata", "findings", "paths", "sources"],
                "metadata.schema_version identifies the result contract. Findings and paths embed evidence records.",
            ),
            _contract(
                "evidence",
                "Atomic evidence record used by findings, paths, calibration, and execution annotations.",
                ["type", "key", "value", "confidence"],
                "type and confidence are enums; key is a stable, non-empty evidence identifier; raw is an optional object.",
            ),
            _contract(
                "lab-profile",
                "Offline calibration profile that maps known lab policy states to observed RelayX signatures.",
                ["profile_id", "target_family", "states"],
                "Each state must provide match criteria, calibrated_state, confidence, promotion, why, and limitations.",
            ),
            _contract(
                "lab-corpus",
                "Offline lab signature corpus extracted from an existing RelayX result.",
                ["metadata", "opsec", "provenance", "endpoint_build", "drift_baseline", "captures"],
                "Captures preserve observed_signature, expected lab labels, raw RelayX evidence, provenance, endpoint build metadata, drift baseline, and capture-level review state.",
            ),
            _contract(
                "lab-provenance",
                "Lab corpus provenance and operator review report generated by relayx lab-provenance.",
                ["name", "version", "tool", "tool_version", "status", "summary", "corpuses", "capture_reviews"],
                "Reports whether corpus provenance, endpoint build metadata, drift baseline, and capture-level operator review are sufficient to support promotion review.",
            ),
            _contract(
                "lab-stability",
                "Repeat-capture lab stability report generated by relayx lab-stability.",
                ["name", "version", "tool", "tool_version", "status", "summary", "policy_states"],
                "Policy-state rows record capture counts, stable signature ratio, drift keys, missing signature keys, and promotion downgrade reasons.",
            ),
            _contract(
                "lab-differential",
                "Lab response differential report generated by relayx lab-diff.",
                ["name", "version", "tool", "tool_version", "status", "summary", "pairs"],
                "Pairs compare stable policy-state signatures, changed keys, discriminator keys, context-only keys, and promotion support.",
            ),
            _contract(
                "evidence-report",
                "Evidence completeness report generated by relayx evidence-report.",
                ["name", "version", "tool", "tool_version", "status", "summary", "records"],
                "Records audit finding/path evidence counts, confidence, source taxonomy, protocol judgement keys, missing contract fields, and remaining uncertainty.",
            ),
            _contract(
                "execution-record",
                "Guarded validation or controlled execution audit record.",
                ["run_id", "tool", "mode", "path_id", "module", "guardrails", "result"],
                "Records operator context, selected module, guardrail outcomes, expected telemetry, actions, and boundaries.",
            ),
            _contract(
                "module-manifest",
                "Execution adapter manifest, either one module object or an object with a modules list.",
                ["key", "label", "version", "supported", "reason", "modes", "adapter"],
                "Manifests describe adapter boundaries, lab-only status, one-shot timeout behavior, expected telemetry, evidence capture, credential/listener policies, and forbidden actions.",
            ),
            _contract(
                "opsec-policy",
                "OPSEC policy document used by validation, execution, and source planning.",
                ["name", "max_noise", "max_timebox_seconds"],
                "Policies define noise ceilings, scope requirements, confirmed-mode context, and forbidden execution boundaries.",
            ),
            _contract(
                "route-report",
                "Route and pivot awareness report generated by relayx routes.",
                ["name", "version", "source_count", "target_count", "routes"],
                "Routes describe modeled source-to-target reachability, pivot types, hop count, route risk, and remaining uncertainty.",
            ),
            _contract(
                "bundle-manifest",
                "Enterprise handoff bundle manifest generated by relayx bundle.",
                ["name", "version", "tool", "tool_version", "artifact_count", "artifacts", "validation"],
                "Artifacts record relative path, format, schema kind, validity, bytes, and SHA256 for release-safe handoff.",
            ),
            _contract(
                "quality-gate",
                "CI and release quality gate report generated by relayx quality-gate.",
                ["name", "version", "tool", "tool_version", "status", "summary", "checks"],
                "Quality gate checks package metadata, schema contracts, fixtures, enterprise docs, and CI workflows.",
            ),
            _contract(
                "opengraph",
                "RelayX graph export for BloodHound/OpenGraph-style ingestion.",
                ["metadata", "graph"],
                "Graph nodes require id, kinds, and properties; graph edges require kind, start, end, and properties.",
            ),
            _contract(
                "jsonl",
                "Enterprise event stream export.",
                ["event_type"],
                "Each line is one JSON object with a stable relayx.* event_type.",
            ),
            _contract(
                "csv",
                "Spreadsheet-oriented enterprise export.",
                _CSV_HEADER,
                "Header order is stable for SIEM/spreadsheet ingestion.",
            ),
        ],
        "enums": {
            "status": sorted(_STATUS_VALUES),
            "confidence": sorted(_CONFIDENCE_VALUES),
            "evidence_type": sorted(_EVIDENCE_TYPE_VALUES),
            "impact": sorted(_IMPACT_VALUES),
            "noise": sorted(_NOISE_VALUES),
            "execution_mode": sorted(_EXECUTION_MODES),
            "promotion": sorted(_PROMOTION_VALUES),
        },
    }


def schema_contracts_to_json() -> str:
    return json.dumps(schema_contracts(), indent=2, sort_keys=True)


def render_schema_contracts() -> str:
    catalog = schema_contracts()
    lines = [
        "RelayX Schema Contracts",
        "",
        f"Schema version: {catalog['schema_version']}",
        "",
        "Kinds:",
    ]
    for row in catalog["kinds"]:
        required = ", ".join(row["required"])
        lines.append(f"  - {row['kind']}: {row['description']}")
        lines.append(f"    required: {required}")
        lines.append(f"    contract: {row['contract']}")
    lines.extend(["", "Core evidence contract:"])
    lines.append("  - type: " + ", ".join(catalog["enums"]["evidence_type"]))
    lines.append("  - confidence: " + ", ".join(catalog["enums"]["confidence"]))
    lines.append("  - key: stable non-empty identifier")
    lines.append("  - value: observed, inferred, unsupported, or error value")
    lines.append("  - raw: optional object with protocol-specific supporting material")
    return "\n".join(lines)


def validate_schema_path(path: str, kind: str = "auto") -> SchemaValidationReport:
    requested_kind = _normalize_kind(kind)
    target = Path(path)
    if target.is_dir():
        files = _schema_files_for_directory(target, requested_kind)
        if not files:
            report = SchemaFileReport(
                path=str(target),
                kind=requested_kind,
                requested_kind=requested_kind,
                valid=False,
                issues=[
                    SchemaIssue(
                        "error",
                        "$",
                        "Directory contains no files matching the requested schema kind.",
                        expected=_expected_suffixes(requested_kind),
                    )
                ],
            )
            return SchemaValidationReport(str(target), requested_kind, [report])
        reports = [_validate_file(file, requested_kind) for file in files]
        return SchemaValidationReport(str(target), requested_kind, reports)
    report = _validate_file(target, requested_kind)
    return SchemaValidationReport(str(target), requested_kind, [report])


def validate_schema_object(data: Any, kind: str = "auto", path: str = "$") -> SchemaFileReport:
    requested_kind = _normalize_kind(kind)
    actual_kind = _infer_kind(data) if requested_kind == "auto" else requested_kind
    issues: list[SchemaIssue] = []
    validator = _VALIDATORS.get(actual_kind)
    if validator is None:
        _issue(
            issues,
            path,
            f"Unable to infer RelayX schema kind for object.",
            expected=", ".join(SCHEMA_KINDS),
            actual=_type_name(data),
        )
        actual_kind = "unknown"
    else:
        validator(data, path, issues)
    return SchemaFileReport(
        path=path,
        kind=actual_kind,
        requested_kind=requested_kind,
        valid=not _has_errors(issues),
        issues=issues,
    )


def schema_validation_to_json(report: SchemaValidationReport) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)


def render_schema_validation(report: SchemaValidationReport) -> str:
    summary = report.summary
    lines = [
        "RelayX Schema Validation",
        "",
        f"Path        : {report.path}",
        f"Kind        : {report.kind}",
        f"Schema      : v{SCHEMA_VERSION}",
        f"Valid       : {str(report.valid).lower()}",
        f"Files       : {summary['valid_files']}/{summary['files']} valid",
        f"Issues      : {summary['errors']} errors, {summary['warnings']} warnings",
    ]
    for file in report.files:
        lines.extend(["", f"{file.path} [{file.kind}] {'valid' if file.valid else 'invalid'}"])
        if not file.issues:
            lines.append("  no issues")
            continue
        for issue in file.issues:
            detail = f"  - {issue.severity}: {issue.path}: {issue.message}"
            if issue.expected:
                detail += f" expected={issue.expected}"
            if issue.actual:
                detail += f" actual={issue.actual}"
            lines.append(detail)
    return "\n".join(lines)


def _contract(kind: str, description: str, required: list[str], contract: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "description": description,
        "required": required,
        "contract": contract,
    }


def _normalize_kind(kind: str) -> str:
    value = (kind or "auto").strip().lower().replace("_", "-")
    aliases = {
        "labprofile": "lab-profile",
        "lab_profile": "lab-profile",
        "labcorpus": "lab-corpus",
        "lab_corpus": "lab-corpus",
        "labprovenance": "lab-provenance",
        "lab_provenance": "lab-provenance",
        "labprov": "lab-provenance",
        "lab-prov": "lab-provenance",
        "labstability": "lab-stability",
        "lab_stability": "lab-stability",
        "labdiff": "lab-differential",
        "lab_diff": "lab-differential",
        "lab-diff": "lab-differential",
        "labdifferential": "lab-differential",
        "lab_differential": "lab-differential",
        "evidencereport": "evidence-report",
        "evidence_report": "evidence-report",
        "evidence-audit": "evidence-report",
        "evidenceaudit": "evidence-report",
        "evidence_audit": "evidence-report",
        "execution": "execution-record",
        "execution_record": "execution-record",
        "module": "module-manifest",
        "module_manifest": "module-manifest",
        "bundle": "bundle-manifest",
        "bundle_manifest": "bundle-manifest",
        "quality": "quality-gate",
        "quality_gate": "quality-gate",
        "open-graph": "opengraph",
        "bloodhound": "opengraph",
    }
    value = aliases.get(value, value)
    if value == "auto" or value in SCHEMA_KINDS:
        return value
    raise ValueError(f"unsupported schema kind: {kind}")


def _schema_files_for_directory(root: Path, kind: str) -> list[Path]:
    suffixes = {
        "jsonl": {".jsonl"},
        "csv": {".csv"},
        "auto": {".json", ".jsonl", ".csv"},
    }.get(kind, {".json"})
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in suffixes)


def _expected_suffixes(kind: str) -> str:
    if kind == "jsonl":
        return "*.jsonl"
    if kind == "csv":
        return "*.csv"
    if kind == "auto":
        return "*.json, *.jsonl, *.csv"
    return "*.json"


def _validate_file(path: Path, requested_kind: str) -> SchemaFileReport:
    if not path.exists():
        return SchemaFileReport(
            path=str(path),
            kind=requested_kind,
            requested_kind=requested_kind,
            valid=False,
            issues=[SchemaIssue("error", "$", "File does not exist.")],
        )
    suffix = path.suffix.lower()
    if requested_kind == "csv" or (requested_kind == "auto" and suffix == ".csv"):
        return _validate_csv_file(path, requested_kind)
    if requested_kind == "jsonl" or (requested_kind == "auto" and suffix == ".jsonl"):
        return _validate_jsonl_file(path, requested_kind)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return SchemaFileReport(
            path=str(path),
            kind=requested_kind,
            requested_kind=requested_kind,
            valid=False,
            issues=[
                SchemaIssue(
                    "error",
                    "$",
                    "File is not valid JSON.",
                    actual=f"line {exc.lineno}, column {exc.colno}: {exc.msg}",
                )
            ],
        )
    except OSError as exc:
        return SchemaFileReport(
            path=str(path),
            kind=requested_kind,
            requested_kind=requested_kind,
            valid=False,
            issues=[SchemaIssue("error", "$", "Unable to read file.", actual=str(exc))],
        )
    return validate_schema_object(data, requested_kind, path=str(path))


def _validate_csv_file(path: Path, requested_kind: str) -> SchemaFileReport:
    issues: list[SchemaIssue] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, None)
            rows = list(reader)
    except OSError as exc:
        _issue(issues, "$", "Unable to read CSV file.", actual=str(exc))
        header = None
        rows = []
    if header != _CSV_HEADER:
        _issue(
            issues,
            "$.header",
            "CSV header does not match the RelayX enterprise export contract.",
            expected=", ".join(_CSV_HEADER),
            actual=", ".join(header or []),
        )
    for index, row in enumerate(rows, start=2):
        if len(row) != len(_CSV_HEADER):
            _issue(
                issues,
                f"$.rows[{index}]",
                "CSV row length does not match the header.",
                expected=str(len(_CSV_HEADER)),
                actual=str(len(row)),
            )
            continue
        record_type = row[0]
        if record_type not in {"finding", "path"}:
            _issue(
                issues,
                f"$.rows[{index}].record_type",
                "Unknown RelayX CSV record type.",
                expected="finding or path",
                actual=record_type,
            )
    return SchemaFileReport(str(path), "csv", requested_kind, not _has_errors(issues), issues)


def _validate_jsonl_file(path: Path, requested_kind: str) -> SchemaFileReport:
    issues: list[SchemaIssue] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        lines = []
        _issue(issues, "$", "Unable to read JSONL file.", actual=str(exc))
    if not lines:
        _issue(issues, "$", "JSONL export must contain at least one event.")
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            _issue(issues, f"$.lines[{index}]", "JSONL contains an empty line.", severity="warning")
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            _issue(
                issues,
                f"$.lines[{index}]",
                "Line is not valid JSON.",
                actual=f"column {exc.colno}: {exc.msg}",
            )
            continue
        _validate_jsonl_event(row, f"$.lines[{index}]", issues)
    return SchemaFileReport(str(path), "jsonl", requested_kind, not _has_errors(issues), issues)


def _validate_jsonl_event(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    event_type = data.get("event_type")
    if not _expect_nonempty_string(event_type, f"{path}.event_type", issues):
        return
    if event_type not in _JSONL_EVENT_TYPES:
        _issue(
            issues,
            f"{path}.event_type",
            "Unknown RelayX JSONL event type.",
            expected=", ".join(sorted(_JSONL_EVENT_TYPES)),
            actual=str(event_type),
        )
    if event_type == "relayx.scan":
        _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
        _expect_nonempty_string(data.get("version"), f"{path}.version", issues)
    elif event_type == "relayx.source":
        _validate_source(data, path, issues)
    elif event_type == "relayx.finding":
        _validate_finding(data, path, issues)
    elif event_type == "relayx.path":
        _validate_path_record(data, path, issues)
    elif event_type == "relayx.control":
        _expect_nonempty_string(data.get("control"), f"{path}.control", issues)


def _infer_kind(data: Any) -> str:
    if isinstance(data, dict):
        metadata = data.get("metadata")
        if isinstance(metadata, dict):
            if metadata.get("format") == "bloodhound-opengraph":
                return "opengraph"
            if metadata.get("mode") == "lab_signature_corpus":
                return "lab-corpus"
        if {"metadata", "findings", "paths", "sources"}.issubset(data):
            return "result"
        if {"profile_id", "target_family", "states"}.issubset(data):
            return "lab-profile"
        if {"captures", "metadata"}.issubset(data):
            return "lab-corpus"
        if {"name", "version", "tool", "tool_version", "status", "summary", "corpuses", "capture_reviews"}.issubset(data) and data.get("name") == "RelayX lab corpus provenance":
            return "lab-provenance"
        if {"name", "version", "tool", "tool_version", "status", "summary", "policy_states"}.issubset(data) and data.get("name") == "RelayX lab capture stability":
            return "lab-stability"
        if {"name", "version", "tool", "tool_version", "status", "summary", "pairs"}.issubset(data) and data.get("name") == "RelayX lab response differential":
            return "lab-differential"
        if {"name", "version", "tool", "tool_version", "status", "summary", "records"}.issubset(data) and data.get("name") == "RelayX evidence report":
            return "evidence-report"
        if {"graph", "metadata"}.issubset(data):
            return "opengraph"
        if {"type", "key", "value"}.issubset(data):
            return "evidence"
        if {"run_id", "tool", "mode", "path_id", "module", "guardrails", "result"}.issubset(data):
            return "execution-record"
        if {"key", "label", "modes", "adapter"}.issubset(data) or "modules" in data:
            return "module-manifest"
        if {"name", "max_noise", "max_timebox_seconds"}.issubset(data) and (
            "allowed_network_actions" in data or "allow_auth_validation" in data
        ):
            return "opsec-policy"
        if {"name", "version", "source_count", "target_count", "routes"}.issubset(data) and data.get("name") == "RelayX route awareness":
            return "route-report"
        if {"name", "version", "tool", "tool_version", "artifact_count", "artifacts", "validation"}.issubset(data) and data.get("name") == "RelayX enterprise bundle":
            return "bundle-manifest"
        if {"name", "version", "tool", "tool_version", "status", "summary", "checks"}.issubset(data) and data.get("name") == "RelayX quality gate":
            return "quality-gate"
    if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        if all({"key", "label", "modes", "adapter"}.issubset(item) for item in data):
            return "module-manifest"
    return "unknown"


def _validate_result(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    metadata = _object_field(data, "metadata", path, issues)
    if metadata is not None:
        _validate_result_metadata(metadata, f"{path}.metadata", issues)
    for field_name, validator in (
        ("findings", _validate_finding),
        ("paths", _validate_path_record),
        ("sources", _validate_source),
    ):
        rows = _list_field(data, field_name, path, issues)
        if rows is None:
            continue
        for index, row in enumerate(rows):
            validator(row, f"{path}.{field_name}[{index}]", issues)


def _validate_result_metadata(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
        if data.get("schema_version") != SCHEMA_VERSION:
            _issue(
                issues,
                f"{path}.schema_version",
                "Unsupported RelayX result schema version.",
                expected=str(SCHEMA_VERSION),
                actual=str(data.get("schema_version")),
            )
    else:
        _issue(
            issues,
            f"{path}.schema_version",
            "Result metadata does not declare schema_version; treating as RelayX schema v1 compatibility data.",
            severity="warning",
            expected=str(SCHEMA_VERSION),
        )
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    if data.get("tool") and data.get("tool") != "RelayX":
        _issue(issues, f"{path}.tool", "Unexpected tool value for RelayX result.", severity="warning", actual=str(data.get("tool")))
    _expect_nonempty_string(data.get("version"), f"{path}.version", issues)
    if "mode" in data:
        _expect_nonempty_string(data.get("mode"), f"{path}.mode", issues)
    if "active" in data:
        _expect_bool(data.get("active"), f"{path}.active", issues)
    _expect_int(data.get("target_count"), f"{path}.target_count", issues)
    _expect_int(data.get("source_count"), f"{path}.source_count", issues)
    for key in ("started_at", "finished_at"):
        if key in data and data.get(key) not in {"", None}:
            _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    if "operation_control" in data and data.get("operation_control") is not None:
        _expect_object(data.get("operation_control"), f"{path}.operation_control", issues)
    for field_name in ("expected_telemetry", "rollback"):
        if field_name in data:
            _list_of_strings_field(data, field_name, path, issues, required=False)


def _validate_evidence(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_enum(data.get("type"), _EVIDENCE_TYPE_VALUES, f"{path}.type", issues)
    _expect_nonempty_string(data.get("key"), f"{path}.key", issues)
    if "value" not in data:
        _issue(issues, f"{path}.value", "Evidence is missing value.")
    _expect_enum(data.get("confidence"), _CONFIDENCE_VALUES, f"{path}.confidence", issues)
    if "detail" in data and data.get("detail") is not None:
        _expect_string(data.get("detail"), f"{path}.detail", issues)
    if "raw" in data and data.get("raw") is not None:
        _expect_object(data.get("raw"), f"{path}.raw", issues)
    key = data.get("key")
    if isinstance(key, str) and any(char.isspace() for char in key):
        _issue(issues, f"{path}.key", "Evidence keys should be stable identifiers without whitespace.", severity="warning")


def _validate_finding(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("host"), f"{path}.host", issues)
    _expect_int(data.get("port"), f"{path}.port", issues)
    if isinstance(data.get("port"), int) and not 0 <= data["port"] <= 65535:
        _issue(issues, f"{path}.port", "Port is outside the TCP/UDP range.", expected="0..65535", actual=str(data["port"]))
    _expect_nonempty_string(data.get("protocol"), f"{path}.protocol", issues)
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    _expect_enum(data.get("status"), _STATUS_VALUES, f"{path}.status", issues)
    _expect_enum(data.get("confidence"), _CONFIDENCE_VALUES, f"{path}.confidence", issues)
    _expect_enum(data.get("impact"), _IMPACT_VALUES, f"{path}.impact", issues)
    if "summary" in data:
        _expect_string(data.get("summary"), f"{path}.summary", issues)
    evidence = _list_field(data, "evidence", path, issues)
    if evidence is not None:
        for index, row in enumerate(evidence):
            _validate_evidence(row, f"{path}.evidence[{index}]", issues)
        if not evidence and data.get("status") in {"relayable", "candidate"}:
            _issue(issues, f"{path}.evidence", "Relayable or candidate findings should include evidence.", severity="warning")
    for field_name in ("blockers", "fixes", "opsec_notes"):
        _list_of_strings_field(data, field_name, path, issues, required=False)
    if "error" in data:
        _expect_string(data.get("error"), f"{path}.error", issues)


def _validate_path_record(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    for key in ("id", "source", "transport", "target", "target_service", "summary"):
        _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    _expect_enum(data.get("status"), _STATUS_VALUES, f"{path}.status", issues)
    _expect_enum(data.get("impact"), _IMPACT_VALUES, f"{path}.impact", issues)
    _expect_enum(data.get("confidence"), _CONFIDENCE_VALUES, f"{path}.confidence", issues)
    _expect_number(data.get("score"), f"{path}.score", issues)
    evidence = _list_field(data, "evidence", path, issues)
    if evidence is not None:
        for index, row in enumerate(evidence):
            _validate_evidence(row, f"{path}.evidence[{index}]", issues)
        if not evidence and data.get("status") in {"relayable", "candidate"}:
            _issue(issues, f"{path}.evidence", "Relayable or candidate paths should include evidence.", severity="warning")
    for field_name in ("blockers", "fixes", "opsec_notes"):
        _list_of_strings_field(data, field_name, path, issues, required=False)


def _validate_source(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("host"), f"{path}.host", issues)
    capabilities = _object_field(data, "capabilities", path, issues, required=False)
    if capabilities is not None:
        for key, value in capabilities.items():
            _expect_bool(value, f"{path}.capabilities.{key}", issues)
    for field_name in ("tags", "routes", "notes", "subnets"):
        _list_of_strings_field(data, field_name, path, issues, required=False)
    for field_name in ("session", "session_id", "segment"):
        if field_name in data:
            _expect_string(data.get(field_name), f"{path}.{field_name}", issues)
    route_hops = _list_field(data, "route_hops", path, issues, required=False)
    if route_hops is not None:
        for index, hop in enumerate(route_hops):
            hop_path = f"{path}.route_hops[{index}]"
            if not _expect_object(hop, hop_path, issues):
                continue
            for field_name in ("id", "name", "kind", "type", "transport", "pivot", "via", "risk", "risk_level", "noise", "noise_level"):
                if field_name in hop:
                    _expect_string(hop.get(field_name), f"{hop_path}.{field_name}", issues)
            for field_name in ("networks", "subnets", "routes", "cidrs", "hosts", "targets", "reachable_hosts", "notes"):
                _list_of_strings_field(hop, field_name, hop_path, issues, required=False)
            for field_name in ("requires_listener", "listener", "exposes_listener"):
                if field_name in hop:
                    _expect_bool(hop.get(field_name), f"{hop_path}.{field_name}", issues)
    if "noise_limit" in data:
        _expect_enum(data.get("noise_limit"), _NOISE_VALUES, f"{path}.noise_limit", issues)


def _validate_lab_profile(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    for key in ("profile_id", "target_family"):
        _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    for key in ("service", "description"):
        if key in data:
            _expect_string(data.get(key), f"{path}.{key}", issues)
    _list_of_strings_field(data, "discriminators", path, issues, required=False)
    states = _list_field(data, "states", path, issues)
    if states is None:
        return
    if not states:
        _issue(issues, f"{path}.states", "Lab profile must contain at least one calibration state.")
    seen_names: set[str] = set()
    for index, state in enumerate(states):
        state_path = f"{path}.states[{index}]"
        if not _expect_object(state, state_path, issues):
            continue
        name = state.get("name")
        _expect_nonempty_string(name, f"{state_path}.name", issues)
        if isinstance(name, str):
            if name in seen_names:
                _issue(issues, f"{state_path}.name", "Duplicate calibration state name.", actual=name)
            seen_names.add(name)
        _expect_nonempty_string(state.get("calibrated_state"), f"{state_path}.calibrated_state", issues)
        _expect_enum(state.get("confidence"), _CONFIDENCE_VALUES, f"{state_path}.confidence", issues)
        _expect_enum(state.get("promotion"), _PROMOTION_VALUES, f"{state_path}.promotion", issues)
        _expect_nonempty_string(state.get("why"), f"{state_path}.why", issues)
        match = _object_field(state, "match", state_path, issues)
        if match is not None and not match:
            _issue(issues, f"{state_path}.match", "Calibration state match object must not be empty.")
        _list_of_strings_field(state, "limitations", state_path, issues, required=True)


def _validate_lab_corpus(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    metadata = _object_field(data, "metadata", path, issues)
    if metadata is not None:
        _expect_nonempty_string(metadata.get("tool"), f"{path}.metadata.tool", issues)
        _expect_nonempty_string(metadata.get("version"), f"{path}.metadata.version", issues)
        _expect_nonempty_string(metadata.get("mode"), f"{path}.metadata.mode", issues)
        if metadata.get("mode") != "lab_signature_corpus":
            _issue(issues, f"{path}.metadata.mode", "Lab corpus mode must be lab_signature_corpus.", actual=str(metadata.get("mode")))
        if "schema_version" in metadata:
            _expect_int(metadata.get("schema_version"), f"{path}.metadata.schema_version", issues)
        _expect_int(metadata.get("finding_count"), f"{path}.metadata.finding_count", issues)
    opsec = _object_field(data, "opsec", path, issues)
    if opsec is not None:
        if "network_actions_recorded" in opsec:
            _expect_bool(opsec.get("network_actions_recorded"), f"{path}.opsec.network_actions_recorded", issues)
        _list_of_strings_field(opsec, "notes", f"{path}.opsec", issues, required=False)
        _list_of_strings_field(opsec, "limitations", f"{path}.opsec", issues, required=False)
    provenance = _object_field(data, "provenance", path, issues, required=False)
    if provenance is None:
        _issue(issues, f"{path}.provenance", "Lab corpus does not declare provenance; run relayx lab-provenance before promotion review.", severity="warning")
    else:
        _validate_lab_corpus_provenance(provenance, f"{path}.provenance", issues)
    endpoint_build = _object_field(data, "endpoint_build", path, issues, required=False)
    if endpoint_build is None:
        _issue(issues, f"{path}.endpoint_build", "Lab corpus does not declare endpoint build metadata.", severity="warning")
    else:
        _validate_endpoint_build(endpoint_build, f"{path}.endpoint_build", issues)
    drift_baseline = _object_field(data, "drift_baseline", path, issues, required=False)
    if drift_baseline is None:
        _issue(issues, f"{path}.drift_baseline", "Lab corpus does not declare a drift baseline.", severity="warning")
    else:
        _validate_drift_baseline(drift_baseline, f"{path}.drift_baseline", issues)
    captures = _list_field(data, "captures", path, issues)
    if captures is None:
        return
    for index, capture in enumerate(captures):
        capture_path = f"{path}.captures[{index}]"
        if not _expect_object(capture, capture_path, issues):
            continue
        for key in ("finding_ref", "host", "protocol", "finding_name", "target_family"):
            _expect_nonempty_string(capture.get(key), f"{capture_path}.{key}", issues)
        if "signature_id" in capture:
            _expect_nonempty_string(capture.get("signature_id"), f"{capture_path}.signature_id", issues)
        _expect_int(capture.get("port"), f"{capture_path}.port", issues)
        _expect_enum(capture.get("status"), _STATUS_VALUES, f"{capture_path}.status", issues)
        _expect_enum(capture.get("confidence"), _CONFIDENCE_VALUES, f"{capture_path}.confidence", issues)
        _object_field(capture, "observed_signature", capture_path, issues)
        if "expected" in capture:
            expected = capture.get("expected")
            if _expect_object(expected, f"{capture_path}.expected", issues):
                if "confidence" in expected:
                    _expect_enum(expected.get("confidence"), _CONFIDENCE_VALUES, f"{capture_path}.expected.confidence", issues)
                if "promotion" in expected:
                    _expect_enum(expected.get("promotion"), _PROMOTION_VALUES, f"{capture_path}.expected.promotion", issues)
                for key in ("policy_state", "classification", "calibrated_state", "promotion_reason"):
                    if key in expected:
                        _expect_string(expected.get(key), f"{capture_path}.expected.{key}", issues)
                _list_of_strings_field(expected, "remaining_uncertainty", f"{capture_path}.expected", issues, required=False)
        review = _object_field(capture, "review", capture_path, issues, required=False)
        if review is None:
            _issue(issues, f"{capture_path}.review", "Capture does not declare review status; it cannot support promotion review.", severity="warning")
        else:
            _validate_capture_review(review, f"{capture_path}.review", issues)
        raw_evidence = _list_field(capture, "raw_evidence", capture_path, issues, required=False)
        if raw_evidence is not None:
            for evidence_index, evidence in enumerate(raw_evidence):
                _validate_evidence(evidence, f"{capture_path}.raw_evidence[{evidence_index}]", issues)


def _validate_lab_corpus_provenance(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_enum(data.get("corpus_kind"), _LAB_CORPUS_KINDS, f"{path}.corpus_kind", issues)
    _expect_enum(data.get("data_origin"), _LAB_DATA_ORIGINS, f"{path}.data_origin", issues)
    _expect_nonempty_string(data.get("capture_source"), f"{path}.capture_source", issues)
    _expect_nonempty_string(data.get("capture_method"), f"{path}.capture_method", issues)
    _expect_enum(data.get("review_status"), _LAB_REVIEW_STATUSES, f"{path}.review_status", issues)
    for key in ("authorization_ref", "operator", "reviewed_by", "reviewed_at", "review_reason"):
        if key in data:
            _expect_string(data.get(key), f"{path}.{key}", issues)


def _validate_endpoint_build(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    for key in ("platform", "server_role", "os_version", "product", "product_version", "policy_matrix"):
        _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    for key in ("authentication_provider", "domain_role", "patch_level"):
        if key in data:
            _expect_string(data.get(key), f"{path}.{key}", issues)
    _list_of_strings_field(data, "notes", path, issues, required=False)
    for key in ("auth_provider_order", "enabled_modules"):
        _list_of_strings_field(data, key, path, issues, required=False)
    for key in ("tls_configuration", "policy_configuration"):
        if key in data:
            _expect_object(data.get(key), f"{path}.{key}", issues)


def _validate_drift_baseline(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("baseline_id"), f"{path}.baseline_id", issues)
    _expect_int(data.get("minimum_repeated_captures"), f"{path}.minimum_repeated_captures", issues)
    _list_of_strings_field(data, "stable_required_keys", path, issues, required=True)
    _list_of_strings_field(data, "known_unstable_keys", path, issues, required=True)
    _list_of_strings_field(data, "notes", path, issues, required=False)


def _validate_capture_review(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_enum(data.get("status"), _LAB_REVIEW_STATUSES, f"{path}.status", issues)
    _expect_enum(data.get("promotion_decision"), _LAB_PROMOTION_DECISIONS, f"{path}.promotion_decision", issues)
    for key in ("reviewed_by", "reviewed_at", "reason"):
        if key in data:
            _expect_string(data.get(key), f"{path}.{key}", issues)
    _list_of_strings_field(data, "limitations", path, issues, required=False)


def _validate_lab_provenance(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if data.get("name") != "RelayX lab corpus provenance":
        _issue(issues, f"{path}.name", "Unexpected lab provenance report name.", severity="warning", actual=str(data.get("name")))
    _expect_int(data.get("version"), f"{path}.version", issues)
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    _expect_nonempty_string(data.get("tool_version"), f"{path}.tool_version", issues)
    _expect_enum(data.get("status"), _LAB_PROVENANCE_STATUSES, f"{path}.status", issues)
    if "target_family" in data:
        _expect_string(data.get("target_family"), f"{path}.target_family", issues)
    summary = _object_field(data, "summary", path, issues)
    if summary is not None:
        for key in (
            "corpuses",
            "captures",
            "synthetic_corpuses",
            "operator_supplied_corpuses",
            "real_lab_corpuses",
            "external_corpuses",
            "missing_provenance",
            "missing_endpoint_build",
            "missing_drift_baseline",
            "promotion_hints",
            "promotion_ready",
            "unreviewed_promotion_hints",
            "fixture_only_promotion_hints",
            "pending_reviews",
            "reviewed_captures",
        ):
            _expect_int(summary.get(key), f"{path}.summary.{key}", issues)
    corpuses = _list_field(data, "corpuses", path, issues)
    if corpuses is not None:
        if summary is not None and isinstance(summary.get("corpuses"), int) and summary["corpuses"] != len(corpuses):
            _issue(
                issues,
                f"{path}.summary.corpuses",
                "summary.corpuses must match the number of corpus records.",
                expected=str(len(corpuses)),
                actual=str(summary["corpuses"]),
            )
        for index, row in enumerate(corpuses):
            _validate_lab_provenance_corpus_row(row, f"{path}.corpuses[{index}]", issues)
    reviews = _list_field(data, "capture_reviews", path, issues)
    if reviews is not None:
        if summary is not None and isinstance(summary.get("captures"), int) and summary["captures"] != len(reviews):
            _issue(
                issues,
                f"{path}.summary.captures",
                "summary.captures must match the number of capture review records.",
                expected=str(len(reviews)),
                actual=str(summary["captures"]),
            )
        for index, row in enumerate(reviews):
            _validate_lab_provenance_capture_row(row, f"{path}.capture_reviews[{index}]", issues)
    blocks = _list_field(data, "promotion_blocks", path, issues, required=False)
    if blocks is not None:
        for index, row in enumerate(blocks):
            row_path = f"{path}.promotion_blocks[{index}]"
            if not _expect_object(row, row_path, issues):
                continue
            for key in ("corpus", "finding_ref", "target_family", "policy_state", "expected_promotion"):
                _expect_string(row.get(key), f"{row_path}.{key}", issues)
            _list_of_strings_field(row, "reasons", row_path, issues, required=True)
    if "confidence_contract" in data:
        contract = _object_field(data, "confidence_contract", path, issues)
        if contract is not None:
            _expect_int(contract.get("version"), f"{path}.confidence_contract.version", issues)
            _expect_nonempty_string(contract.get("evidence_model"), f"{path}.confidence_contract.evidence_model", issues)


def _validate_lab_provenance_corpus_row(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    for key in ("corpus", "source_path", "capture_source", "capture_method", "authorization_ref", "operator"):
        _expect_string(data.get(key), f"{path}.{key}", issues)
    _expect_enum(data.get("status"), _LAB_PROVENANCE_STATUSES, f"{path}.status", issues)
    _expect_enum(data.get("corpus_kind"), _LAB_CORPUS_KINDS, f"{path}.corpus_kind", issues)
    _expect_enum(data.get("data_origin"), _LAB_DATA_ORIGINS, f"{path}.data_origin", issues)
    _expect_enum(data.get("review_status"), _LAB_REVIEW_STATUSES, f"{path}.review_status", issues)
    for key in ("endpoint_build_complete", "drift_baseline_complete"):
        _expect_bool(data.get(key), f"{path}.{key}", issues)
    for key in ("capture_count", "promotion_hints", "promotion_ready", "baseline_minimum_repeated_captures"):
        _expect_int(data.get(key), f"{path}.{key}", issues)
    for key in ("missing_provenance_keys", "missing_endpoint_build_keys", "missing_drift_baseline_keys", "reasons"):
        _list_of_strings_field(data, key, path, issues, required=False)


def _validate_lab_provenance_capture_row(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    for key in ("corpus", "finding_ref", "signature_id", "target_family", "policy_state", "reviewed_by", "reviewed_at"):
        _expect_string(data.get(key), f"{path}.{key}", issues)
    _expect_enum(data.get("expected_promotion"), _PROMOTION_VALUES, f"{path}.expected_promotion", issues)
    _expect_enum(data.get("data_origin"), _LAB_DATA_ORIGINS, f"{path}.data_origin", issues)
    _expect_enum(data.get("review_status"), _LAB_REVIEW_STATUSES, f"{path}.review_status", issues)
    _expect_enum(data.get("promotion_decision"), _LAB_PROMOTION_DECISIONS, f"{path}.promotion_decision", issues)
    _expect_bool(data.get("promotion_ready"), f"{path}.promotion_ready", issues)
    _list_of_strings_field(data, "reasons", path, issues, required=False)


def _validate_lab_stability(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if data.get("name") != "RelayX lab capture stability":
        _issue(issues, f"{path}.name", "Unexpected lab stability report name.", severity="warning", actual=str(data.get("name")))
    _expect_int(data.get("version"), f"{path}.version", issues)
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    _expect_nonempty_string(data.get("tool_version"), f"{path}.tool_version", issues)
    _expect_enum(data.get("status"), {"pass", "warn", "fail"}, f"{path}.status", issues)
    if "target_family" in data:
        _expect_string(data.get("target_family"), f"{path}.target_family", issues)
    summary = _object_field(data, "summary", path, issues)
    if summary is not None:
        for key in ("corpuses", "captures", "policy_states", "stable", "missing", "insufficient", "drifted", "min_captures"):
            _expect_int(summary.get(key), f"{path}.summary.{key}", issues)
        for key in ("stable_threshold", "average_consistency_score"):
            _expect_number(summary.get(key), f"{path}.summary.{key}", issues)
    rows = _list_field(data, "policy_states", path, issues)
    if rows is None:
        return
    if summary is not None and isinstance(summary.get("policy_states"), int) and summary["policy_states"] != len(rows):
        _issue(
            issues,
            f"{path}.summary.policy_states",
            "summary.policy_states must match the number of policy state records.",
            expected=str(len(rows)),
            actual=str(summary["policy_states"]),
        )
    for index, row in enumerate(rows):
        row_path = f"{path}.policy_states[{index}]"
        if not _expect_object(row, row_path, issues):
            continue
        for key in ("id", "target_family", "policy_state", "dominant_signature_id", "promotion_expectation", "recommended_profile_promotion"):
            if key in row:
                _expect_string(row.get(key), f"{row_path}.{key}", issues)
        _expect_enum(row.get("status"), _LAB_STABILITY_STATUSES, f"{row_path}.status", issues)
        if "recommended_profile_promotion" in row:
            _expect_enum(row.get("recommended_profile_promotion"), _LAB_STABILITY_RECOMMENDATIONS, f"{row_path}.recommended_profile_promotion", issues)
        for key in ("required", "drift_detected"):
            _expect_bool(row.get(key), f"{row_path}.{key}", issues)
        for key in ("capture_count", "min_captures", "distinct_signature_count"):
            _expect_int(row.get(key), f"{row_path}.{key}", issues)
        for key in ("stable_threshold", "consistency_score"):
            _expect_number(row.get(key), f"{row_path}.{key}", issues)
        for key in ("drift_keys", "signature_ids", "missing_signature_keys", "promotion_downgrade_reasons", "remaining_uncertainty"):
            _list_of_strings_field(row, key, row_path, issues, required=False)
        for key in ("dominant_signature", "signature_counts", "confidence_counts", "promotion_counts"):
            if key in row:
                _expect_object(row.get(key), f"{row_path}.{key}", issues)
        capture_refs = _list_field(row, "capture_refs", row_path, issues, required=False)
        if capture_refs is not None:
            for ref_index, ref in enumerate(capture_refs):
                ref_path = f"{row_path}.capture_refs[{ref_index}]"
                if not _expect_object(ref, ref_path, issues):
                    continue
                for key in ("corpus", "finding_ref", "signature_id", "policy_state", "host", "protocol"):
                    _expect_string(ref.get(key), f"{ref_path}.{key}", issues)
                _expect_int(ref.get("port"), f"{ref_path}.port", issues)
    downgrades = _list_field(data, "promotion_downgrades", path, issues, required=False)
    if downgrades is not None:
        for index, downgrade in enumerate(downgrades):
            downgrade_path = f"{path}.promotion_downgrades[{index}]"
            if not _expect_object(downgrade, downgrade_path, issues):
                continue
            for key in ("target_family", "policy_state", "recommended_profile_promotion"):
                _expect_string(downgrade.get(key), f"{downgrade_path}.{key}", issues)
            _list_of_strings_field(downgrade, "reasons", downgrade_path, issues, required=True)
    if "confidence_contract" in data:
        contract = _object_field(data, "confidence_contract", path, issues)
        if contract is not None:
            _expect_int(contract.get("version"), f"{path}.confidence_contract.version", issues)
            _expect_nonempty_string(contract.get("evidence_model"), f"{path}.confidence_contract.evidence_model", issues)


def _validate_lab_differential(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if data.get("name") != "RelayX lab response differential":
        _issue(issues, f"{path}.name", "Unexpected lab differential report name.", severity="warning", actual=str(data.get("name")))
    _expect_int(data.get("version"), f"{path}.version", issues)
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    _expect_nonempty_string(data.get("tool_version"), f"{path}.tool_version", issues)
    _expect_enum(data.get("status"), {"pass", "warn", "fail"}, f"{path}.status", issues)
    if "target_family" in data:
        _expect_string(data.get("target_family"), f"{path}.target_family", issues)
    summary = _object_field(data, "summary", path, issues)
    if summary is not None:
        for key in (
            "pairs",
            "differential",
            "context_only",
            "indistinguishable",
            "missing",
            "unstable",
            "promotion_relevant",
            "promotable_candidates",
            "pair_filters",
            "unmatched_pair_filters",
            "min_captures",
        ):
            _expect_int(summary.get(key), f"{path}.summary.{key}", issues)
        _expect_number(summary.get("stable_threshold"), f"{path}.summary.stable_threshold", issues)
    for key in ("pair_filters", "unmatched_pair_filters"):
        _list_of_strings_field(data, key, path, issues, required=False)
    pairs = _list_field(data, "pairs", path, issues)
    if pairs is None:
        return
    if summary is not None and isinstance(summary.get("pairs"), int) and summary["pairs"] != len(pairs):
        _issue(
            issues,
            f"{path}.summary.pairs",
            "summary.pairs must match the number of pair records.",
            expected=str(len(pairs)),
            actual=str(summary["pairs"]),
        )
    for index, pair in enumerate(pairs):
        pair_path = f"{path}.pairs[{index}]"
        if not _expect_object(pair, pair_path, issues):
            continue
        for key in (
            "id",
            "target_family",
            "left_policy_state",
            "right_policy_state",
            "left_status",
            "right_status",
            "left_signature_id",
            "right_signature_id",
            "left_promotion_expectation",
            "right_promotion_expectation",
            "left_recommended_profile_promotion",
            "right_recommended_profile_promotion",
        ):
            if key in pair:
                _expect_string(pair.get(key), f"{pair_path}.{key}", issues)
        _expect_enum(pair.get("status"), _LAB_DIFFERENTIAL_STATUSES, f"{pair_path}.status", issues)
        _expect_enum(pair.get("promotion_support"), _LAB_PROMOTION_SUPPORT, f"{pair_path}.promotion_support", issues)
        for key in ("expected_promotion_relevant", "promotable_candidate"):
            _expect_bool(pair.get(key), f"{pair_path}.{key}", issues)
        for key in ("left_capture_count", "right_capture_count"):
            _expect_int(pair.get(key), f"{pair_path}.{key}", issues)
        if "changed_keys" in pair:
            _expect_object(pair.get("changed_keys"), f"{pair_path}.changed_keys", issues)
        for key in ("discriminator_keys", "context_only_keys", "reasons", "remaining_uncertainty"):
            _list_of_strings_field(pair, key, pair_path, issues, required=False)
    if "stability_summary" in data:
        _expect_object(data.get("stability_summary"), f"{path}.stability_summary", issues)
    if "confidence_contract" in data:
        contract = _object_field(data, "confidence_contract", path, issues)
        if contract is not None:
            _expect_int(contract.get("version"), f"{path}.confidence_contract.version", issues)
            _expect_nonempty_string(contract.get("evidence_model"), f"{path}.confidence_contract.evidence_model", issues)


def _validate_evidence_report(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if data.get("name") != "RelayX evidence report":
        _issue(issues, f"{path}.name", "Unexpected evidence report name.", severity="warning", actual=str(data.get("name")))
    _expect_int(data.get("version"), f"{path}.version", issues)
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    _expect_nonempty_string(data.get("tool_version"), f"{path}.tool_version", issues)
    if "result_version" in data:
        _expect_string(data.get("result_version"), f"{path}.result_version", issues)
    _expect_enum(data.get("status"), _GUARDRAIL_STATES, f"{path}.status", issues)
    summary = _object_field(data, "summary", path, issues)
    if summary is not None:
        for key in (
            "findings",
            "paths",
            "records",
            "complete",
            "warning",
            "failed",
            "protocol_judgement_required",
            "protocol_judgement_complete",
            "missing_evidence",
            "missing_policy_inference",
            "missing_remaining_uncertainty",
            "unknown_confidence",
            "taxonomy_generic",
        ):
            _expect_int(summary.get(key), f"{path}.summary.{key}", issues)
        for key in ("source_categories", "judgement_roles"):
            if key in summary:
                _expect_object(summary.get(key), f"{path}.summary.{key}", issues)
    records = _list_field(data, "records", path, issues)
    if records is None:
        return
    if summary is not None and isinstance(summary.get("records"), int) and summary["records"] != len(records):
        _issue(
            issues,
            f"{path}.summary.records",
            "summary.records must match the number of evidence report records.",
            expected=str(len(records)),
            actual=str(summary["records"]),
        )
    for index, record in enumerate(records):
        record_path = f"{path}.records[{index}]"
        if not _expect_object(record, record_path, issues):
            continue
        for key in ("id", "target", "service", "target_family", "response_classification", "response_subclassification", "policy_inference", "oracle_signature"):
            if key in record:
                _expect_string(record.get(key), f"{record_path}.{key}", issues)
        _expect_enum(record.get("kind"), {"finding", "path"}, f"{record_path}.kind", issues)
        _expect_enum(record.get("record_status"), _STATUS_VALUES, f"{record_path}.record_status", issues)
        _expect_enum(record.get("record_confidence"), _CONFIDENCE_VALUES, f"{record_path}.record_confidence", issues)
        _expect_enum(record.get("status"), _GUARDRAIL_STATES, f"{record_path}.status", issues)
        _expect_bool(record.get("protocol_judgement_required"), f"{record_path}.protocol_judgement_required", issues)
        for key in ("evidence_count", "unknown_confidence_evidence"):
            _expect_int(record.get(key), f"{record_path}.{key}", issues)
        for key in ("evidence_type_counts", "evidence_confidence_counts", "source_category_counts", "judgement_role_counts"):
            if key in record:
                _expect_object(record.get(key), f"{record_path}.{key}", issues)
        for key in ("evidence_keys", "remaining_uncertainty", "missing_contract_keys", "reasons"):
            _list_of_strings_field(record, key, record_path, issues, required=False)
        sources = _list_field(record, "evidence_sources", record_path, issues, required=False)
        if sources is not None:
            if isinstance(record.get("evidence_count"), int) and record["evidence_count"] != len(sources):
                _issue(
                    issues,
                    f"{record_path}.evidence_sources",
                    "evidence_sources must match evidence_count.",
                    expected=str(record["evidence_count"]),
                    actual=str(len(sources)),
                )
            for source_index, source in enumerate(sources):
                source_path = f"{record_path}.evidence_sources[{source_index}]"
                if not _expect_object(source, source_path, issues):
                    continue
                _expect_nonempty_string(source.get("key"), f"{source_path}.key", issues)
                _expect_enum(source.get("type"), _EVIDENCE_TYPE_VALUES, f"{source_path}.type", issues)
                _expect_enum(source.get("confidence"), _CONFIDENCE_VALUES, f"{source_path}.confidence", issues)
                _expect_enum(source.get("source_category"), _EVIDENCE_SOURCE_CATEGORIES, f"{source_path}.source_category", issues)
                _expect_enum(source.get("judgement_role"), _EVIDENCE_JUDGEMENT_ROLES, f"{source_path}.judgement_role", issues)
                if "detail" in source:
                    _expect_string(source.get("detail"), f"{source_path}.detail", issues)
    if "confidence_contract" in data:
        contract = _object_field(data, "confidence_contract", path, issues)
        if contract is not None:
            _expect_int(contract.get("version"), f"{path}.confidence_contract.version", issues)
            _expect_nonempty_string(contract.get("evidence_model"), f"{path}.confidence_contract.evidence_model", issues)
            if "source_taxonomy_version" in contract:
                _expect_int(contract.get("source_taxonomy_version"), f"{path}.confidence_contract.source_taxonomy_version", issues)
            if "source_categories" in contract:
                _expect_object(contract.get("source_categories"), f"{path}.confidence_contract.source_categories", issues)


def _validate_execution_record(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("run_id"), f"{path}.run_id", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    if data.get("tool") != "RelayX":
        _issue(issues, f"{path}.tool", "Unexpected tool value for RelayX execution record.", severity="warning", actual=str(data.get("tool")))
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_enum(data.get("mode"), _EXECUTION_MODES, f"{path}.mode", issues)
    _expect_nonempty_string(data.get("path_id"), f"{path}.path_id", issues)
    for key in ("decision", "rule_id", "source", "target", "transport", "target_service", "noise"):
        if key in data:
            _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    if "noise" in data:
        _expect_enum(data.get("noise"), _NOISE_VALUES, f"{path}.noise", issues)
    if "timebox_seconds" in data:
        _expect_int(data.get("timebox_seconds"), f"{path}.timebox_seconds", issues)
    module = _object_field(data, "module", path, issues)
    if module is not None:
        _validate_module(module, f"{path}.module", issues)
    adapter_sdk = _object_field(data, "adapter_sdk", path, issues, required=False)
    if adapter_sdk is not None:
        if "sdk_version" in adapter_sdk:
            _expect_int(adapter_sdk.get("sdk_version"), f"{path}.adapter_sdk.sdk_version", issues)
        _expect_nonempty_string(adapter_sdk.get("adapter"), f"{path}.adapter_sdk.adapter", issues)
        if "registered" in adapter_sdk:
            _expect_bool(adapter_sdk.get("registered"), f"{path}.adapter_sdk.registered", issues)
        for key in ("credential_policy", "listener_policy", "network_action"):
            if key in adapter_sdk:
                _expect_nonempty_string(adapter_sdk.get(key), f"{path}.adapter_sdk.{key}", issues)
        for key in ("credential_policy_safe", "listener_policy_safe", "support_consistent"):
            if key in adapter_sdk:
                _expect_bool(adapter_sdk.get(key), f"{path}.adapter_sdk.{key}", issues)
        for key in ("one_shot", "lab_only"):
            if key in adapter_sdk:
                _expect_bool(adapter_sdk.get(key), f"{path}.adapter_sdk.{key}", issues)
        if "timeout_seconds" in adapter_sdk:
            _expect_int(adapter_sdk.get("timeout_seconds"), f"{path}.adapter_sdk.timeout_seconds", issues)
        for key in ("expected_telemetry", "evidence_capture"):
            if key in adapter_sdk:
                _list_of_strings_field(adapter_sdk, key, f"{path}.adapter_sdk", issues, required=False)
    guardrails = _list_field(data, "guardrails", path, issues)
    if guardrails is not None:
        for index, guardrail in enumerate(guardrails):
            guardrail_path = f"{path}.guardrails[{index}]"
            if not _expect_object(guardrail, guardrail_path, issues):
                continue
            _expect_nonempty_string(guardrail.get("key"), f"{guardrail_path}.key", issues)
            _expect_enum(guardrail.get("state"), _GUARDRAIL_STATES, f"{guardrail_path}.state", issues)
            _expect_nonempty_string(guardrail.get("reason"), f"{guardrail_path}.reason", issues)
    result = _object_field(data, "result", path, issues)
    if result is not None:
        _expect_nonempty_string(result.get("state"), f"{path}.result.state", issues)
        _expect_nonempty_string(result.get("reason"), f"{path}.result.reason", issues)
    for key in ("preconditions", "hardening_gates", "operator_guardrails", "planned_steps", "expected_telemetry", "rollback", "boundaries"):
        if key in data:
            _list_field(data, key, path, issues, required=False)
    if "artifacts" in data:
        _list_of_strings_field(data, "artifacts", path, issues, required=False)
    execution_contract = _object_field(data, "execution_contract", path, issues, required=False)
    if execution_contract is not None:
        for key in ("lab_only", "one_shot"):
            if key in execution_contract:
                _expect_bool(execution_contract.get(key), f"{path}.execution_contract.{key}", issues)
        for key in ("timeout_behavior",):
            if key in execution_contract:
                _expect_nonempty_string(execution_contract.get(key), f"{path}.execution_contract.{key}", issues)
        for key in ("module_timeout_seconds", "request_timebox_seconds", "effective_timeout_seconds"):
            if key in execution_contract:
                _expect_int(execution_contract.get(key), f"{path}.execution_contract.{key}", issues)
        for key in ("expected_telemetry", "evidence_capture"):
            if key in execution_contract:
                _list_of_strings_field(execution_contract, key, f"{path}.execution_contract", issues, required=False)
    lifecycle = _list_field(data, "adapter_lifecycle", path, issues, required=False)
    if lifecycle is not None:
        for index, row in enumerate(lifecycle):
            row_path = f"{path}.adapter_lifecycle[{index}]"
            if not _expect_object(row, row_path, issues):
                continue
            for key in ("phase", "state", "reason"):
                _expect_nonempty_string(row.get(key), f"{row_path}.{key}", issues)
            if "network_action" in row:
                _expect_bool(row.get("network_action"), f"{row_path}.network_action", issues)
    actions = _list_field(data, "actions", path, issues, required=False)
    if actions is not None:
        for index, action in enumerate(actions):
            action_path = f"{path}.actions[{index}]"
            if not _expect_object(action, action_path, issues):
                continue
            _expect_nonempty_string(action.get("type"), f"{action_path}.type", issues)
            _expect_nonempty_string(action.get("state"), f"{action_path}.state", issues)
            if "network_action" in action:
                _expect_bool(action.get("network_action"), f"{action_path}.network_action", issues)


def _validate_module_manifest(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if isinstance(data, list):
        modules = data
    elif isinstance(data, dict) and "modules" in data:
        modules = _list_field(data, "modules", path, issues) or []
    else:
        modules = [data]
    for index, module in enumerate(modules):
        module_path = path if len(modules) == 1 else f"{path}.modules[{index}]"
        _validate_module(module, module_path, issues)


def _validate_module(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    for key in ("key", "label", "version", "reason", "adapter"):
        _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    if "description" in data:
        _expect_string(data.get("description"), f"{path}.description", issues)
    for key in ("credential_policy", "listener_policy"):
        if key in data:
            _expect_nonempty_string(data.get(key), f"{path}.{key}", issues)
    _expect_bool(data.get("supported"), f"{path}.supported", issues)
    for key in ("lab_only", "one_shot"):
        if key in data:
            _expect_bool(data.get(key), f"{path}.{key}", issues)
    if "timeout_behavior" in data:
        _expect_nonempty_string(data.get("timeout_behavior"), f"{path}.timeout_behavior", issues)
    if "timeout_seconds" in data:
        _expect_int(data.get("timeout_seconds"), f"{path}.timeout_seconds", issues)
    for key in ("target_families", "source_capabilities", "modes", "lifecycle", "requires", "artifacts", "forbidden_actions"):
        rows = _list_of_strings_field(data, key, path, issues, required=key in {"target_families", "source_capabilities", "modes"})
        if key == "modes" and rows is not None:
            for index, mode in enumerate(rows):
                _expect_enum(mode, _EXECUTION_MODES, f"{path}.modes[{index}]", issues)
    for key in ("expected_telemetry", "evidence_capture"):
        _list_of_strings_field(data, key, path, issues, required=False)
    if data.get("supported") and data.get("network_action") not in {"none", "", None}:
        forbidden = set(data.get("forbidden_actions") or [])
        if not {"credential_capture", "credential_forwarding"}.intersection(forbidden):
            _issue(
                issues,
                f"{path}.forbidden_actions",
                "Supported network modules should explicitly forbid unsafe credential handling unless separately governed.",
                severity="warning",
            )


def _validate_opsec_policy(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if "description" in data:
        _expect_string(data.get("description"), f"{path}.description", issues)
    _expect_enum(data.get("max_noise"), _NOISE_VALUES, f"{path}.max_noise", issues)
    _expect_int(data.get("max_timebox_seconds"), f"{path}.max_timebox_seconds", issues)
    for key in (
        "require_scope_for_armed",
        "require_scope_for_confirmed",
        "require_scope_for_source_plan",
        "require_scope_for_connect_check",
        "require_scope_for_listener",
        "require_scope_for_callback",
        "require_confirm_for_confirmed",
        "require_operator_for_confirmed",
        "require_reason_for_confirmed",
        "require_audit_for_confirmed",
        "allow_auth_validation",
        "require_reprobe_for_auth_validation",
        "allow_source_trigger_execution",
        "allow_credential_capture",
        "allow_credential_forwarding",
        "allow_listener",
    ):
        if key in data:
            _expect_bool(data.get(key), f"{path}.{key}", issues)
    for key in (
        "allowed_network_actions",
        "blocked_source_capabilities",
        "blocked_target_families",
        "allowed_target_families",
        "notes",
    ):
        _list_of_strings_field(data, key, path, issues, required=False)


def _validate_opengraph(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    metadata = _object_field(data, "metadata", path, issues)
    if metadata is not None:
        _expect_nonempty_string(metadata.get("source_kind"), f"{path}.metadata.source_kind", issues)
        _expect_nonempty_string(metadata.get("format"), f"{path}.metadata.format", issues)
        if metadata.get("format") != "bloodhound-opengraph":
            _issue(issues, f"{path}.metadata.format", "OpenGraph export format must be bloodhound-opengraph.", actual=str(metadata.get("format")))
        _expect_int(metadata.get("schema_version"), f"{path}.metadata.schema_version", issues)
        if "field_contract_version" in metadata:
            _expect_int(metadata.get("field_contract_version"), f"{path}.metadata.field_contract_version", issues)
    mapping = _object_field(data, "mapping", path, issues, required=False)
    if mapping is not None:
        _object_field(mapping, "node_kinds", f"{path}.mapping", issues, required=False)
        _object_field(mapping, "edge_kinds", f"{path}.mapping", issues, required=False)
    graph = _object_field(data, "graph", path, issues)
    if graph is None:
        return
    nodes = _list_field(graph, "nodes", f"{path}.graph", issues)
    if nodes is not None:
        for index, node in enumerate(nodes):
            node_path = f"{path}.graph.nodes[{index}]"
            if not _expect_object(node, node_path, issues):
                continue
            _expect_nonempty_string(node.get("id"), f"{node_path}.id", issues)
            _list_of_strings_field(node, "kinds", node_path, issues, required=True)
            _object_field(node, "properties", node_path, issues)
    edges = _list_field(graph, "edges", f"{path}.graph", issues)
    if edges is not None:
        for index, edge in enumerate(edges):
            edge_path = f"{path}.graph.edges[{index}]"
            if not _expect_object(edge, edge_path, issues):
                continue
            if "id" in edge:
                _expect_nonempty_string(edge.get("id"), f"{edge_path}.id", issues)
            _expect_nonempty_string(edge.get("kind"), f"{edge_path}.kind", issues)
            for endpoint in ("start", "end"):
                endpoint_data = _object_field(edge, endpoint, edge_path, issues)
                if endpoint_data is not None:
                    _expect_nonempty_string(endpoint_data.get("value"), f"{edge_path}.{endpoint}.value", issues)
                    _expect_nonempty_string(endpoint_data.get("match_by"), f"{edge_path}.{endpoint}.match_by", issues)
            _object_field(edge, "properties", edge_path, issues)


def _validate_route_report(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    _expect_int(data.get("version"), f"{path}.version", issues)
    _expect_int(data.get("source_count"), f"{path}.source_count", issues)
    _expect_int(data.get("target_count"), f"{path}.target_count", issues)
    if "target_protocol" in data:
        _expect_string(data.get("target_protocol"), f"{path}.target_protocol", issues)
    routes = _list_field(data, "routes", path, issues)
    if routes is None:
        return
    for index, row in enumerate(routes):
        row_path = f"{path}.routes[{index}]"
        if not _expect_object(row, row_path, issues):
            continue
        _expect_nonempty_string(row.get("source"), f"{row_path}.source", issues)
        state = row.get("state")
        _expect_enum(state, _ROUTE_STATES, f"{row_path}.state", issues)
        _expect_bool(row.get("reachable"), f"{row_path}.reachable", issues)
        if "target" in row:
            _expect_string(row.get("target"), f"{row_path}.target", issues)
        if "confidence" in row:
            _expect_enum(row.get("confidence"), _CONFIDENCE_VALUES, f"{row_path}.confidence", issues)
        if "hop_count" in row:
            _expect_int(row.get("hop_count"), f"{row_path}.hop_count", issues)
        if "pivot_types" in row:
            _list_of_strings_field(row, "pivot_types", row_path, issues, required=False)
        if "risk_score" in row:
            _expect_number(row.get("risk_score"), f"{row_path}.risk_score", issues)
        if "risk_level" in row:
            _expect_enum(row.get("risk_level"), _ROUTE_RISK_LEVELS, f"{row_path}.risk_level", issues)
        if "noise" in row:
            _expect_enum(row.get("noise"), _NOISE_VALUES, f"{row_path}.noise", issues)
        for field_name in ("reasons", "limitations"):
            if field_name in row:
                _list_of_strings_field(row, field_name, row_path, issues, required=False)
        for field_name in ("matched_hops", "all_hops"):
            hops = _list_field(row, field_name, row_path, issues, required=False)
            if hops is None:
                continue
            for hop_index, hop in enumerate(hops):
                hop_path = f"{row_path}.{field_name}[{hop_index}]"
                if not _expect_object(hop, hop_path, issues):
                    continue
                if "kind" in hop:
                    _expect_nonempty_string(hop.get("kind"), f"{hop_path}.kind", issues)


def _validate_bundle_manifest(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if data.get("name") != "RelayX enterprise bundle":
        _issue(issues, f"{path}.name", "Bundle manifest name must be RelayX enterprise bundle.", actual=str(data.get("name")))
    _expect_int(data.get("version"), f"{path}.version", issues)
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    _expect_nonempty_string(data.get("tool_version"), f"{path}.tool_version", issues)
    if "created_at" in data:
        _expect_nonempty_string(data.get("created_at"), f"{path}.created_at", issues)
    source = _object_field(data, "source", path, issues, required=False)
    if source is not None:
        for key in ("target_count", "source_count", "finding_count", "path_count"):
            if key in source:
                _expect_int(source.get(key), f"{path}.source.{key}", issues)
    _expect_int(data.get("artifact_count"), f"{path}.artifact_count", issues)
    artifacts = _list_field(data, "artifacts", path, issues)
    if artifacts is not None:
        if isinstance(data.get("artifact_count"), int) and data["artifact_count"] != len(artifacts):
            _issue(
                issues,
                f"{path}.artifact_count",
                "artifact_count must match the number of artifact records.",
                expected=str(len(artifacts)),
                actual=str(data["artifact_count"]),
            )
        for index, artifact in enumerate(artifacts):
            artifact_path = f"{path}.artifacts[{index}]"
            if not _expect_object(artifact, artifact_path, issues):
                continue
            _expect_nonempty_string(artifact.get("path"), f"{artifact_path}.path", issues)
            _expect_nonempty_string(artifact.get("format"), f"{artifact_path}.format", issues)
            if "schema_kind" in artifact:
                _expect_string(artifact.get("schema_kind"), f"{artifact_path}.schema_kind", issues)
            _expect_bool(artifact.get("valid"), f"{artifact_path}.valid", issues)
            for key in ("errors", "warnings", "bytes"):
                _expect_int(artifact.get(key), f"{artifact_path}.{key}", issues)
            sha256 = artifact.get("sha256")
            if _expect_nonempty_string(sha256, f"{artifact_path}.sha256", issues):
                clean = str(sha256)
                if len(clean) != 64 or any(char not in "0123456789abcdef" for char in clean):
                    _issue(issues, f"{artifact_path}.sha256", "sha256 must be 64 lowercase hexadecimal characters.")
    validation = _object_field(data, "validation", path, issues)
    if validation is not None:
        _expect_bool(validation.get("valid"), f"{path}.validation.valid", issues)
        for key in ("errors", "warnings"):
            _expect_int(validation.get(key), f"{path}.validation.{key}", issues)
        _list_of_strings_field(validation, "invalid_artifacts", f"{path}.validation", issues, required=False)


def _validate_quality_gate(data: Any, path: str, issues: list[SchemaIssue]) -> None:
    if not _expect_object(data, path, issues):
        return
    _expect_nonempty_string(data.get("name"), f"{path}.name", issues)
    if data.get("name") != "RelayX quality gate":
        _issue(issues, f"{path}.name", "Quality gate name must be RelayX quality gate.", actual=str(data.get("name")))
    _expect_int(data.get("version"), f"{path}.version", issues)
    if "schema_version" in data:
        _expect_int(data.get("schema_version"), f"{path}.schema_version", issues)
    _expect_nonempty_string(data.get("tool"), f"{path}.tool", issues)
    _expect_nonempty_string(data.get("tool_version"), f"{path}.tool_version", issues)
    _expect_enum(data.get("status"), {"pass", "fail"}, f"{path}.status", issues)
    contract = _object_field(data, "contract", path, issues, required=False)
    if contract is not None:
        _list_of_strings_field(contract, "required_checks", f"{path}.contract", issues, required=False)
        _list_of_strings_field(contract, "stable_fields", f"{path}.contract", issues, required=False)
        if "exit_code_on_failure" in contract:
            _expect_int(contract.get("exit_code_on_failure"), f"{path}.contract.exit_code_on_failure", issues)
        if "release_automation_ready" in contract:
            _expect_bool(contract.get("release_automation_ready"), f"{path}.contract.release_automation_ready", issues)
    summary = _object_field(data, "summary", path, issues)
    if summary is not None:
        for key in ("checks", "passed", "failed", "warnings"):
            _expect_int(summary.get(key), f"{path}.summary.{key}", issues)
    checks = _list_field(data, "checks", path, issues)
    if checks is None:
        return
    if summary is not None and isinstance(summary.get("checks"), int) and summary["checks"] != len(checks):
        _issue(
            issues,
            f"{path}.summary.checks",
            "summary.checks must match the number of check records.",
            expected=str(len(checks)),
            actual=str(summary["checks"]),
        )
    for index, check in enumerate(checks):
        check_path = f"{path}.checks[{index}]"
        if not _expect_object(check, check_path, issues):
            continue
        _expect_nonempty_string(check.get("name"), f"{check_path}.name", issues)
        _expect_enum(check.get("status"), {"pass", "fail", "warn"}, f"{check_path}.status", issues)
        _expect_nonempty_string(check.get("message"), f"{check_path}.message", issues)
        if "evidence" in check:
            _expect_object(check.get("evidence"), f"{check_path}.evidence", issues)


def _object_field(data: dict[str, Any], key: str, path: str, issues: list[SchemaIssue], *, required: bool = True) -> dict[str, Any] | None:
    if key not in data:
        if required:
            _issue(issues, f"{path}.{key}", "Missing required object field.")
        return None
    value = data.get(key)
    return value if _expect_object(value, f"{path}.{key}", issues) else None


def _list_field(data: dict[str, Any], key: str, path: str, issues: list[SchemaIssue], *, required: bool = True) -> list[Any] | None:
    if key not in data:
        if required:
            _issue(issues, f"{path}.{key}", "Missing required list field.")
        return None
    value = data.get(key)
    if not isinstance(value, list):
        _issue(issues, f"{path}.{key}", "Expected a list.", expected="list", actual=_type_name(value))
        return None
    return value


def _list_of_strings_field(data: dict[str, Any], key: str, path: str, issues: list[SchemaIssue], *, required: bool) -> list[str] | None:
    rows = _list_field(data, key, path, issues, required=required)
    if rows is None:
        return None
    for index, row in enumerate(rows):
        _expect_string(row, f"{path}.{key}[{index}]", issues)
    return [str(row) for row in rows if isinstance(row, str)]


def _expect_object(value: Any, path: str, issues: list[SchemaIssue]) -> bool:
    if isinstance(value, dict):
        return True
    _issue(issues, path, "Expected an object.", expected="object", actual=_type_name(value))
    return False


def _expect_string(value: Any, path: str, issues: list[SchemaIssue]) -> bool:
    if isinstance(value, str):
        return True
    _issue(issues, path, "Expected a string.", expected="string", actual=_type_name(value))
    return False


def _expect_nonempty_string(value: Any, path: str, issues: list[SchemaIssue]) -> bool:
    if not _expect_string(value, path, issues):
        return False
    if not value.strip():
        _issue(issues, path, "String must not be empty.", expected="non-empty string")
        return False
    return True


def _expect_bool(value: Any, path: str, issues: list[SchemaIssue]) -> bool:
    if isinstance(value, bool):
        return True
    _issue(issues, path, "Expected a boolean.", expected="boolean", actual=_type_name(value))
    return False


def _expect_int(value: Any, path: str, issues: list[SchemaIssue]) -> bool:
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    _issue(issues, path, "Expected an integer.", expected="integer", actual=_type_name(value))
    return False


def _expect_number(value: Any, path: str, issues: list[SchemaIssue]) -> bool:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    _issue(issues, path, "Expected a number.", expected="number", actual=_type_name(value))
    return False


def _expect_enum(value: Any, allowed: set[str], path: str, issues: list[SchemaIssue]) -> bool:
    if isinstance(value, str) and value in allowed:
        return True
    _issue(
        issues,
        path,
        "Value is outside the RelayX schema enum.",
        expected=", ".join(sorted(allowed)),
        actual=str(value),
    )
    return False


def _issue(
    issues: list[SchemaIssue],
    path: str,
    message: str,
    *,
    severity: str = "error",
    expected: str = "",
    actual: str = "",
) -> None:
    issues.append(SchemaIssue(severity=severity, path=path, message=message, expected=expected, actual=actual))


def _has_errors(issues: list[SchemaIssue]) -> bool:
    return any(issue.severity == "error" for issue in issues)


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "list"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


Validator = Callable[[Any, str, list[SchemaIssue]], None]

_VALIDATORS: dict[str, Validator] = {
    "result": _validate_result,
    "evidence": _validate_evidence,
    "lab-profile": _validate_lab_profile,
    "lab-corpus": _validate_lab_corpus,
    "lab-provenance": _validate_lab_provenance,
    "lab-stability": _validate_lab_stability,
    "lab-differential": _validate_lab_differential,
    "evidence-report": _validate_evidence_report,
    "execution-record": _validate_execution_record,
    "module-manifest": _validate_module_manifest,
    "opsec-policy": _validate_opsec_policy,
    "route-report": _validate_route_report,
    "bundle-manifest": _validate_bundle_manifest,
    "quality-gate": _validate_quality_gate,
    "opengraph": _validate_opengraph,
}
