from __future__ import annotations

import csv
import hashlib
import io
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..models import RelayPath, ScanResult, Status, to_plain
from ..outputs import render_csv, render_html, render_json, render_markdown, render_mermaid
from .calculus import assess_path
from .controls import CONTROL_LABELS, control_summary
from .evidence import evidence_value
from .path import remediation_counts


ENTERPRISE_EXPORT_FORMATS = {"opengraph", "jsonl", "csv", "json", "html", "mermaid", "mmd", "markdown", "md"}
ENTERPRISE_BUNDLE_FORMATS = ("opengraph", "jsonl", "csv", "html", "markdown", "mermaid")
ENTERPRISE_FIELD_CONTRACT_VERSION = 1
_BUNDLE_FORMAT_ALIASES = {"md": "markdown", "mmd": "mermaid"}
_BUNDLE_FILENAMES = {
    "opengraph": "relayx-opengraph.json",
    "jsonl": "relayx-events.jsonl",
    "csv": "relayx.csv",
    "html": "relayx-report.html",
    "markdown": "relayx-report.md",
    "mermaid": "relayx-paths.mmd",
}
_BUNDLE_SCHEMA_KINDS = {
    "opengraph": "opengraph",
    "jsonl": "jsonl",
    "csv": "csv",
}
CSV_FIELD_CONTRACT = [
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
JSONL_FIELD_CONTRACT = {
    "common": ["event_type", "event_id", "schema_version", "field_contract_version"],
    "relayx.scan": [
        "tool",
        "version",
        "started_at",
        "finished_at",
        "target_count",
        "source_count",
        "finding_count",
        "path_count",
    ],
    "relayx.path": [
        "id",
        "path_id",
        "source",
        "transport",
        "target",
        "target_service",
        "status",
        "impact",
        "score",
        "rule_id",
        "decision",
        "target_family",
        "source_capability",
        "control_keys",
        "route_state",
        "route_risk_level",
    ],
}
OPENGRAPH_MAPPING = {
    "node_kinds": {
        "RelayXScan": ["tool", "version", "target_count", "source_count", "finding_count", "path_count"],
        "RelayXSource": ["name", "capabilities", "routes", "session", "segment", "noise_limit"],
        "RelayXTarget": ["name"],
        "RelayXTargetService": ["host", "service", "target_family"],
        "RelayXFinding": ["host", "port", "protocol", "name", "status", "confidence", "impact"],
        "RelayXPath": [
            "path_id",
            "source",
            "target",
            "target_service",
            "status",
            "decision",
            "target_family",
            "source_capability",
            "score",
        ],
        "RelayXControl": ["control", "label", "paths", "cumulative_score", "max_impact"],
    },
    "edge_kinds": {
        "RelayXIncludesSource": "scan -> source",
        "RelayXIncludesTarget": "scan -> target",
        "RelayXHasFinding": "target -> finding",
        "RelayXIncludesPath": "scan -> path",
        "RelayXPathSource": "source -> path",
        "RelayXPathTarget": "path -> target service",
        "RelayXCandidateRelay": "source -> target service",
        "RelayXPathMitigatedBy": "path -> defensive control",
    },
}
CONTROL_DEPENDENCIES = {
    "adcs_hardening": ("http_epa", "ntlm_restriction"),
    "http_epa": ("ntlm_restriction",),
    "ldap_channel_binding": ("ldap_signing",),
    "ldap_signing": ("ntlm_restriction",),
    "mssql_epa": ("mssql_service_account_hardening", "ntlm_restriction"),
    "mssql_service_account_hardening": ("mssql_epa",),
    "name_resolution_hardening": ("outbound_auth_egress",),
    "rpc_coercion_reduction": ("outbound_auth_egress",),
    "smb_signing": ("ntlm_restriction",),
    "webclient_hardening": ("outbound_auth_egress", "ntlm_restriction"),
}


def export_result(result: ScanResult, fmt: str) -> str:
    normalized = fmt.lower()
    if normalized == "opengraph":
        return json.dumps(export_opengraph(result), indent=2, sort_keys=True)
    if normalized == "jsonl":
        return export_jsonl(result)
    if normalized == "csv":
        return export_csv(result)
    if normalized == "json":
        return render_json(result)
    if normalized == "html":
        return render_html(result)
    if normalized in {"mermaid", "mmd"}:
        return render_mermaid(result)
    if normalized in {"markdown", "md"}:
        return render_markdown(result)
    raise ValueError(f"unsupported export format: {fmt}")


def write_enterprise_bundle(
    result: ScanResult,
    out_dir: str | Path,
    *,
    formats: list[str] | tuple[str, ...] | None = None,
    include_routes: bool = True,
) -> dict:
    """Write an enterprise handoff bundle and return its manifest."""

    from .routes import assess_route_matrix, route_report_to_json
    from .schema import validate_schema_path

    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []

    result_path = root / "relayx-result.json"
    result_path.write_text(json.dumps(to_plain(result), indent=2, sort_keys=True), encoding="utf-8")
    artifacts.append(_artifact_record(root, result_path, "json", "result", validate_schema_path(str(result_path), "result")))

    for fmt in _normalize_bundle_formats(formats):
        output_path = root / _BUNDLE_FILENAMES[fmt]
        output_path.write_text(export_result(result, fmt), encoding="utf-8")
        schema_kind = _BUNDLE_SCHEMA_KINDS.get(fmt, "")
        schema_report = validate_schema_path(str(output_path), schema_kind) if schema_kind else None
        artifacts.append(_artifact_record(root, output_path, fmt, schema_kind, schema_report))

    targets = sorted({finding.host for finding in result.findings})
    if include_routes and result.sources and targets:
        route_path = root / "relayx-routes.json"
        route_report = assess_route_matrix(result.sources, targets)
        route_path.write_text(route_report_to_json(route_report), encoding="utf-8")
        artifacts.append(
            _artifact_record(root, route_path, "json", "route-report", validate_schema_path(str(route_path), "route-report"))
        )

    manifest = {
        "name": "RelayX enterprise bundle",
        "version": 1,
        "schema_version": 1,
        "tool": result.metadata.tool,
        "tool_version": result.metadata.version,
        "created_at": datetime.now(UTC).isoformat(),
        "source": {
            "target_count": result.metadata.target_count,
            "source_count": result.metadata.source_count,
            "finding_count": len(result.findings),
            "path_count": len(result.paths),
        },
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "validation": _bundle_validation_summary(artifacts),
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def bundle_manifest_to_json(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True)


def render_bundle_manifest(manifest: dict) -> str:
    validation = manifest.get("validation", {})
    lines = [
        "RelayX Enterprise Bundle",
        "",
        f"Tool        : {manifest.get('tool', 'RelayX')} {manifest.get('tool_version', '')}".rstrip(),
        f"Artifacts   : {manifest.get('artifact_count', 0)}",
        f"Valid       : {str(validation.get('valid', False)).lower()}",
        f"Issues      : {validation.get('errors', 0)} errors, {validation.get('warnings', 0)} warnings",
        "",
        "Artifacts:",
    ]
    for artifact in manifest.get("artifacts", []):
        schema_kind = artifact.get("schema_kind") or "rendered"
        validity = "valid" if artifact.get("valid", True) else "invalid"
        lines.append(
            f"  - {artifact.get('path', '')} [{artifact.get('format', '')}/{schema_kind}] "
            f"{validity} bytes={artifact.get('bytes', 0)}"
        )
    return "\n".join(lines)


def export_opengraph(result: ScanResult) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    root_id = "relayx:scan"
    nodes[root_id] = _node(
        root_id,
        ["RelayXScan"],
        {
            "tool": result.metadata.tool,
            "version": result.metadata.version,
            "started_at": result.metadata.started_at,
            "finished_at": result.metadata.finished_at,
            "target_count": result.metadata.target_count,
            "source_count": result.metadata.source_count,
            "finding_count": len(result.findings),
            "path_count": len(result.paths),
        },
    )

    for source in result.sources:
        source_id = _source_id(source.host)
        nodes.setdefault(
            source_id,
            _node(
                source_id,
                ["RelayXSource"],
                {
                    "name": source.host,
                    "capabilities": source.capabilities,
                    "tags": source.tags,
                    "routes": source.routes,
                    "route_hops": source.route_hops,
                    "subnets": source.subnets,
                    "session": source.session,
                    "segment": source.segment,
                    "noise_limit": source.noise_limit.value,
                },
            ),
        )
        edges.append(_edge(root_id, source_id, "RelayXIncludesSource"))

    for finding in result.findings:
        finding_id = _finding_id(finding.host, finding.protocol, finding.port, finding.name)
        target_id = _target_id(finding.host)
        nodes.setdefault(target_id, _node(target_id, ["RelayXTarget"], {"name": finding.host}))
        nodes[finding_id] = _node(
            finding_id,
            ["RelayXFinding"],
            {
                "host": finding.host,
                "port": finding.port,
                "protocol": finding.protocol,
                "name": finding.name,
                "status": finding.status.value,
                "confidence": finding.confidence.value,
                "impact": finding.impact.value,
                "summary": finding.summary,
                "blockers": finding.blockers,
                "fixes": finding.fixes,
            },
        )
        edges.append(_edge(root_id, target_id, "RelayXIncludesTarget"))
        edges.append(_edge(target_id, finding_id, "RelayXHasFinding"))

    for path in result.paths:
        assessment = assess_path(path)
        path_id = _path_id(path.id)
        source_id = _source_id(path.source)
        target_id = _target_service_id(path.target, path.target_service)
        nodes.setdefault(source_id, _node(source_id, ["RelayXSource"], {"name": path.source}))
        nodes[target_id] = _node(
            target_id,
            ["RelayXTargetService"],
            {
                "host": path.target,
                "service": path.target_service,
                "target_family": assessment.target_family,
            },
        )
        nodes[path_id] = _node(
            path_id,
            ["RelayXPath"],
            {
                "path_id": path.id,
                "source": path.source,
                "transport": path.transport,
                "target": path.target,
                "target_service": path.target_service,
                "status": path.status.value,
                "impact": path.impact.value,
                "confidence": path.confidence.value,
                "score": path.score,
                "summary": path.summary,
                "rule_id": assessment.rule_id,
                "decision": assessment.decision,
                "target_family": assessment.target_family,
                "source_capability": str(evidence_value(path, "source_capability", "generic")),
                "route_state": str(evidence_value(path, "route_reachability_state", "")),
                "route_reachable": bool(evidence_value(path, "route_reachable", True)),
                "route_risk_score": evidence_value(path, "route_risk_score", ""),
                "route_risk_level": str(evidence_value(path, "route_risk_level", "")),
                "route_pivot_types": evidence_value(path, "route_pivot_types", []),
                "control_keys": _path_controls(path),
                "blockers": path.blockers,
                "fixes": path.fixes,
            },
        )
        edges.extend(
            [
                _edge(root_id, path_id, "RelayXIncludesPath"),
                _edge(source_id, path_id, "RelayXPathSource"),
                _edge(path_id, target_id, "RelayXPathTarget"),
            ]
        )
        if path.status != Status.BLOCKED:
            edges.append(
                _edge(
                    source_id,
                    target_id,
                    "RelayXCandidateRelay",
                    {
                        "path_id": path.id,
                        "transport": path.transport,
                        "score": path.score,
                        "decision": assessment.decision,
                    },
                )
            )
        for control in _path_controls(path):
            control_id = _control_id(control)
            nodes.setdefault(
                control_id,
                _node(
                    control_id,
                    ["RelayXControl"],
                    {
                        "control": control,
                        "label": CONTROL_LABELS.get(control, control.replace("_", " ").title()),
                    },
                ),
            )
            edges.append(
                _edge(
                    path_id,
                    control_id,
                    "RelayXPathMitigatedBy",
                    {
                        "path_id": path.id,
                        "control": control,
                    },
                )
            )

    for row in control_summary(result.paths):
        control_id = _control_id(row["control"])
        node = nodes.setdefault(
            control_id,
            _node(
                control_id,
                ["RelayXControl"],
                {
                    "control": row["control"],
                    "label": row["label"],
                },
            ),
        )
        node["properties"].update(
            {
                "paths": row["paths"],
                "path_ids": row["path_ids"],
                "cumulative_score": row["cumulative_score"],
                "max_impact": row["max_impact"],
            }
        )

    return {
        "metadata": {
            "source_kind": "RelayX",
            "format": "bloodhound-opengraph",
            "schema_version": 1,
            "field_contract_version": ENTERPRISE_FIELD_CONTRACT_VERSION,
            "description": "RelayX custom OpenGraph export for relay readiness, paths, and remediation context.",
        },
        "mapping": OPENGRAPH_MAPPING,
        "graph": {
            "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
            "edges": _dedupe_edges(edges),
        },
    }


def export_jsonl(result: ScanResult) -> str:
    rows: list[dict] = [
        _event(
            "relayx.scan",
            tool=result.metadata.tool,
            version=result.metadata.version,
            started_at=result.metadata.started_at,
            finished_at=result.metadata.finished_at,
            target_count=result.metadata.target_count,
            source_count=result.metadata.source_count,
            finding_count=len(result.findings),
            path_count=len(result.paths),
            field_contract=JSONL_FIELD_CONTRACT,
        )
    ]
    for source in result.sources:
        rows.append(_event("relayx.source", **to_plain(source)))
    for finding in result.findings:
        rows.append(
            _event(
                "relayx.finding",
                **to_plain(finding),
                event_id=_finding_fingerprint(finding),
                severity=finding.impact.value,
                blocker_count=len(finding.blockers),
                fix_count=len(finding.fixes),
            )
        )
    for path in result.paths:
        assessment = assess_path(path)
        controls = _path_controls(path)
        path_event = {
            **to_plain(path),
            "path_id": path.id,
            "host": path.target,
            "protocol": _path_protocol(path),
            "severity": path.impact.value,
            "rule_id": assessment.rule_id,
            "target_family": assessment.target_family,
            "decision": assessment.decision,
            "source_capability": str(evidence_value(path, "source_capability", "generic")),
            "control_keys": controls,
            "control_labels": [CONTROL_LABELS.get(control, control.replace("_", " ").title()) for control in controls],
            "response_classification": str(evidence_value(path, "relayx_response_classification", "")),
            "response_subclassification": str(evidence_value(path, "relayx_response_subclassification", "")),
            "policy_inference": str(evidence_value(path, "relayx_policy_inference", "")),
            "oracle_signature": str(evidence_value(path, "relayx_oracle_signature", "")),
            "route_state": str(evidence_value(path, "route_reachability_state", "")),
            "route_reachable": bool(evidence_value(path, "route_reachable", True)),
            "route_risk_level": str(evidence_value(path, "route_risk_level", "")),
            "route_risk_score": evidence_value(path, "route_risk_score", ""),
            "remaining_uncertainty": _remaining_uncertainty(path),
        }
        rows.append(
            _event(
                "relayx.path",
                **path_event,
            )
        )
    for row in control_summary(result.paths):
        rows.append(_event("relayx.control", **row, event_id=str(row["control"])))
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


def export_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_FIELD_CONTRACT)
    for finding in result.findings:
        writer.writerow(
            [
                "finding",
                "",
                finding.host,
                finding.port,
                finding.protocol,
                finding.status.value,
                "",
                finding.impact.value,
                finding.confidence.value,
                "",
                "",
                finding.host,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                finding.summary,
                "; ".join(finding.blockers),
                "; ".join(finding.fixes),
                "; ".join(finding.opsec_notes),
                ENTERPRISE_FIELD_CONTRACT_VERSION,
            ]
        )
    for path in result.paths:
        assessment = assess_path(path)
        controls = _path_controls(path)
        writer.writerow(
            [
                "path",
                path.id,
                path.target,
                "",
                "",
                path.status.value,
                path.score,
                path.impact.value,
                path.confidence.value,
                path.source,
                path.transport,
                path.target,
                path.target_service,
                assessment.rule_id,
                assessment.decision,
                assessment.target_family,
                str(evidence_value(path, "source_capability", "generic")),
                "; ".join(controls),
                "; ".join(CONTROL_LABELS.get(control, control.replace("_", " ").title()) for control in controls),
                str(evidence_value(path, "route_reachability_state", "")),
                str(evidence_value(path, "route_risk_level", "")),
                evidence_value(path, "route_risk_score", ""),
                path.summary,
                "; ".join(path.blockers),
                "; ".join(path.fixes),
                "; ".join(_remaining_uncertainty(path)),
                ENTERPRISE_FIELD_CONTRACT_VERSION,
            ]
        )
    return buf.getvalue()


def diff_results(old: ScanResult, new: ScanResult) -> dict:
    old_paths = {_path_fingerprint(path): path for path in old.paths}
    new_paths = {_path_fingerprint(path): path for path in new.paths}
    added_keys = sorted(set(new_paths) - set(old_paths))
    removed_keys = sorted(set(old_paths) - set(new_paths))
    common_keys = sorted(set(old_paths) & set(new_paths))
    changed = [
        _path_change(old_paths[key], new_paths[key])
        for key in common_keys
        if _path_change(old_paths[key], new_paths[key])["changed"]
    ]
    old_findings = {_finding_fingerprint(finding): finding for finding in old.findings}
    new_findings = {_finding_fingerprint(finding): finding for finding in new.findings}
    old_score = round(sum(path.score for path in old.paths), 2)
    new_score = round(sum(path.score for path in new.paths), 2)
    added_records = [_path_record(new_paths[key]) for key in added_keys]
    removed_records = [_path_record(old_paths[key]) for key in removed_keys]
    control_trends = _control_trends(old.paths, new.paths)
    regressions = [row for row in control_trends if row["trend"] == "regressed"]
    improvements = [row for row in control_trends if row["trend"] == "improved"]
    exposure_trend = _exposure_trend(
        old_score=old_score,
        new_score=new_score,
        added=added_records,
        removed=removed_records,
        changed=changed,
    )
    return {
        "name": "RelayX scan diff",
        "version": 1,
        "field_contract_version": ENTERPRISE_FIELD_CONTRACT_VERSION,
        "summary": {
            "old_paths": len(old.paths),
            "new_paths": len(new.paths),
            "added_paths": len(added_keys),
            "removed_paths": len(removed_keys),
            "changed_paths": len(changed),
            "added_findings": len(set(new_findings) - set(old_findings)),
            "removed_findings": len(set(old_findings) - set(new_findings)),
            "old_score": old_score,
            "new_score": new_score,
            "score_delta": round(new_score - old_score, 2),
            "path_delta": len(new.paths) - len(old.paths),
            "exposure_trend": exposure_trend,
            "remediation_regressions": len(regressions),
            "remediation_improvements": len(improvements),
        },
        "added_paths": added_records,
        "removed_paths": removed_records,
        "changed_paths": changed,
        "added_findings": [_finding_record(new_findings[key]) for key in sorted(set(new_findings) - set(old_findings))],
        "removed_findings": [_finding_record(old_findings[key]) for key in sorted(set(old_findings) - set(new_findings))],
        "control_trends": control_trends,
        "remediation_regressions": regressions,
        "remediation_improvements": improvements,
    }


def render_diff(diff: dict) -> str:
    summary = diff["summary"]
    lines = [
        "RelayX Diff",
        "",
        f"Paths: {summary['old_paths']} -> {summary['new_paths']} "
        f"(+{summary['added_paths']} -{summary['removed_paths']} changed={summary['changed_paths']})",
        f"Findings: +{summary['added_findings']} -{summary['removed_findings']}",
        f"Score: {summary['old_score']} -> {summary['new_score']} (delta={summary.get('score_delta', 0)})",
        f"Trend: {summary.get('exposure_trend', 'unknown')}",
    ]
    if diff["added_paths"]:
        lines.extend(["", "Added Paths:"])
        for row in diff["added_paths"]:
            lines.append(f"  - {row['fingerprint']} score={row['score']} decision={row['decision']}")
    if diff["removed_paths"]:
        lines.extend(["", "Removed Paths:"])
        for row in diff["removed_paths"]:
            lines.append(f"  - {row['fingerprint']} score={row['score']} decision={row['decision']}")
    if diff["changed_paths"]:
        lines.extend(["", "Changed Paths:"])
        for row in diff["changed_paths"]:
            lines.append(f"  - {row['fingerprint']}: {', '.join(row['changes'])}")
    if diff.get("control_trends"):
        lines.extend(["", "Control Trends:"])
        for row in diff["control_trends"]:
            if row["trend"] == "unchanged":
                continue
            lines.append(
                f"  - {row['control']}: {row['old_paths']} -> {row['new_paths']} paths, "
                f"score_delta={row['score_delta']} trend={row['trend']}"
            )
    return "\n".join(lines)


def simulate_fixes(result: ScanResult, fixes: list[str] | None = None, top: int = 10) -> dict:
    requested = [fix.strip() for fix in fixes or [] if fix.strip()]
    candidates = requested or [fix for fix, _, _ in remediation_counts(result.paths)]
    total_score = round(sum(path.score for path in result.paths), 2)
    total_paths = len(result.paths)
    rows = [_simulate_fix(result.paths, fix, total_paths, total_score) for fix in candidates]
    rows = sorted(rows, key=lambda row: (row["score_reduction"], row["paths_reduced"], row["fix"]), reverse=True)
    return {
        "name": "RelayX remediation impact simulation",
        "version": 1,
        "field_contract_version": ENTERPRISE_FIELD_CONTRACT_VERSION,
        "baseline": {
            "paths": total_paths,
            "score": total_score,
            "status_counts": dict(Counter(path.status.value for path in result.paths)),
            "impact_counts": dict(Counter(path.impact.value for path in result.paths)),
            "control_count": len(control_summary(result.paths)),
        },
        "assumptions": [
            "Simulation is an offline estimate from RelayX path evidence and control mapping.",
            "No network validation is performed by simulate-fixes.",
            "Residual exposure remains when other controls still map to remaining paths or when dependencies are not simulated.",
        ],
        "simulations": rows[:top],
    }


def render_simulation(simulation: dict) -> str:
    baseline = simulation["baseline"]
    lines = [
        "RelayX Remediation Simulation",
        "",
        f"Baseline paths={baseline['paths']} score={baseline['score']}",
        "",
        "Fix Impact:",
    ]
    if not simulation["simulations"]:
        lines.append("  No matching fixes available.")
        return "\n".join(lines)
    for index, row in enumerate(simulation["simulations"], start=1):
        lines.append(f"{index}. {row['fix']}")
        lines.append(
            f"   paths {baseline['paths']} -> {row['remaining_paths']} "
            f"(reduced={row['paths_reduced']}); score {baseline['score']} -> {row['remaining_score']} "
            f"(reduced={row['score_reduction']})"
        )
        lines.append(f"   affected: {', '.join(row['affected_path_ids']) or 'none'}")
        residual = row.get("residual_exposure", {})
        lines.append(
            f"   residual: {residual.get('level', 'unknown')} "
            f"paths={residual.get('remaining_paths', row['remaining_paths'])} "
            f"score={residual.get('remaining_score', row['remaining_score'])}"
        )
        dependencies = row.get("control_dependencies", [])
        if dependencies:
            lines.append("   dependencies: " + ", ".join(item["control"] for item in dependencies))
    return "\n".join(lines)


def simulation_to_json(simulation: dict) -> str:
    return json.dumps(simulation, indent=2, sort_keys=True)


def diff_to_json(diff: dict) -> str:
    return json.dumps(diff, indent=2, sort_keys=True)


def _normalize_bundle_formats(formats: list[str] | tuple[str, ...] | None) -> list[str]:
    if not formats:
        return list(ENTERPRISE_BUNDLE_FORMATS)
    normalized: list[str] = []
    for raw in formats:
        for part in str(raw).split(","):
            value = part.strip().lower()
            if not value:
                continue
            if value == "all":
                normalized.extend(ENTERPRISE_BUNDLE_FORMATS)
                continue
            value = _BUNDLE_FORMAT_ALIASES.get(value, value)
            if value not in ENTERPRISE_BUNDLE_FORMATS:
                raise ValueError(f"unsupported bundle format: {raw}")
            normalized.append(value)
    deduped: list[str] = []
    for value in normalized:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _artifact_record(root: Path, path: Path, fmt: str, schema_kind: str, schema_report: Any | None) -> dict[str, Any]:
    summary = schema_report.summary if schema_report is not None else {"errors": 0, "warnings": 0}
    return {
        "path": path.relative_to(root).as_posix(),
        "format": fmt,
        "schema_kind": schema_kind,
        "valid": bool(schema_report.valid) if schema_report is not None else True,
        "errors": int(summary.get("errors", 0)),
        "warnings": int(summary.get("warnings", 0)),
        "bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _bundle_validation_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    errors = sum(int(artifact.get("errors", 0)) for artifact in artifacts)
    warnings = sum(int(artifact.get("warnings", 0)) for artifact in artifacts)
    invalid = [artifact["path"] for artifact in artifacts if not artifact.get("valid", True)]
    return {
        "valid": not invalid and errors == 0,
        "errors": errors,
        "warnings": warnings,
        "invalid_artifacts": invalid,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _simulate_fix(paths: list[RelayPath], fix: str, total_paths: int, total_score: float) -> dict:
    affected = [path for path in paths if _fix_matches(path, fix)]
    affected_ids = {path.id for path in affected}
    remaining = [path for path in paths if path.id not in affected_ids]
    remaining_score = round(sum(path.score for path in remaining), 2)
    control_key = _fix_control_key(fix)
    dependencies = _dependency_records(control_key, remaining) if control_key else []
    residual = _residual_exposure(remaining, total_paths, total_score, dependencies)
    return {
        "fix": fix,
        "control_key": control_key,
        "control_label": CONTROL_LABELS.get(control_key, control_key.replace("_", " ").title()) if control_key else "",
        "control_dependencies": dependencies,
        "affected_path_ids": sorted(affected_ids),
        "paths_reduced": len(affected_ids),
        "remaining_paths": total_paths - len(affected_ids),
        "score_reduction": round(total_score - remaining_score, 2),
        "remaining_score": remaining_score,
        "remaining_status_counts": dict(Counter(path.status.value for path in remaining)),
        "remaining_impact_counts": dict(Counter(path.impact.value for path in remaining)),
        "residual_exposure": residual,
    }


def _fix_matches(path: RelayPath, fix: str) -> bool:
    wanted = fix.strip().lower()
    if not wanted:
        return False
    if wanted.startswith("control:"):
        control = wanted.split(":", 1)[1]
        return control in [item.lower() for item in _path_controls(path)]
    return any(wanted in item.lower() for item in path.fixes)


def _fix_control_key(fix: str) -> str:
    wanted = fix.strip().lower()
    if wanted.startswith("control:"):
        return wanted.split(":", 1)[1].strip()
    for key, label in CONTROL_LABELS.items():
        if key in wanted or label.lower() in wanted:
            return key
    return ""


def _dependency_records(control_key: str, remaining: list[RelayPath]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for dependency in CONTROL_DEPENDENCIES.get(control_key, ()):
        path_ids = sorted(path.id for path in remaining if dependency in _path_controls(path))
        rows.append(
            {
                "control": dependency,
                "label": CONTROL_LABELS.get(dependency, dependency.replace("_", " ").title()),
                "status": "open" if path_ids else "not_observed_on_remaining_paths",
                "remaining_path_ids": path_ids,
                "remaining_paths": len(path_ids),
            }
        )
    return rows


def _residual_exposure(
    remaining: list[RelayPath],
    total_paths: int,
    total_score: float,
    dependencies: list[dict[str, Any]],
) -> dict[str, Any]:
    remaining_score = round(sum(path.score for path in remaining), 2)
    controls = sorted({control for path in remaining for control in _path_controls(path)})
    target_families = Counter(assess_path(path).target_family for path in remaining)
    open_dependencies = [row["control"] for row in dependencies if row["status"] == "open"]
    if not remaining:
        level = "eliminated"
    elif remaining_score >= max(total_score, 0.01):
        level = "unchanged"
    elif remaining_score >= 60 or any(path.impact.value == "critical" for path in remaining):
        level = "critical"
    elif remaining_score >= 30 or any(path.impact.value == "high" for path in remaining):
        level = "high"
    elif remaining_score >= 10:
        level = "medium"
    else:
        level = "low"
    return {
        "level": level,
        "remaining_paths": len(remaining),
        "remaining_path_ratio": round(len(remaining) / total_paths, 4) if total_paths else 0.0,
        "remaining_score": remaining_score,
        "remaining_score_ratio": round(remaining_score / total_score, 4) if total_score else 0.0,
        "remaining_control_keys": controls,
        "remaining_target_families": dict(sorted(target_families.items())),
        "open_dependency_controls": open_dependencies,
    }


def _event(event_type: str, **fields: Any) -> dict[str, Any]:
    explicit_id = str(fields.pop("event_id", "") or "").strip()
    event_key = explicit_id or _stable_event_key(event_type, fields)
    row = {
        "event_type": event_type,
        "event_id": f"relayx:{event_type}:{_slug(event_key)}",
        "schema_version": 1,
        "field_contract_version": ENTERPRISE_FIELD_CONTRACT_VERSION,
    }
    row.update(fields)
    return row


def _stable_event_key(event_type: str, fields: dict[str, Any]) -> str:
    if event_type == "relayx.scan":
        return "scan"
    if event_type == "relayx.source":
        return str(fields.get("host", "source"))
    if event_type == "relayx.path":
        return str(fields.get("id") or fields.get("path_id") or "path")
    if event_type == "relayx.control":
        return str(fields.get("control", "control"))
    return hashlib.sha256(json.dumps(fields, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def _path_controls(path: RelayPath) -> list[str]:
    raw = evidence_value(path, "relayx_controls", []) or []
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list | tuple | set):
        values = [str(item) for item in raw]
    else:
        values = [str(raw)]
    return sorted({value.strip() for value in values if value and value.strip()})


def _remaining_uncertainty(path: RelayPath) -> list[str]:
    values: list[str] = []
    for key in ("relayx_remaining_uncertainty", "remaining_uncertainty"):
        raw = evidence_value(path, key, [])
        if isinstance(raw, str) and raw.strip():
            values.append(raw.strip())
        elif isinstance(raw, list | tuple | set):
            values.extend(str(item).strip() for item in raw if str(item).strip())
    if path.status == Status.CANDIDATE and not values:
        values.append("Candidate requires validation or calibration before promotion.")
    return sorted(dict.fromkeys([*values, *path.opsec_notes]))


def _path_protocol(path: RelayPath) -> str:
    service = path.target_service.split("/", 1)[0].strip().lower()
    if service:
        return service
    return path.transport.split("/", 1)[0].strip().lower()


def _node(node_id: str, kinds: list[str], properties: dict[str, Any]) -> dict:
    return {"id": node_id, "kinds": kinds, "properties": properties}


def _edge(start_id: str, end_id: str, kind: str, properties: dict[str, Any] | None = None) -> dict:
    clean_properties = properties or {}
    return {
        "id": _edge_id(start_id, end_id, kind, clean_properties),
        "kind": kind,
        "start": {"value": start_id, "match_by": "id"},
        "end": {"value": end_id, "match_by": "id"},
        "properties": clean_properties,
    }


def _edge_id(start_id: str, end_id: str, kind: str, properties: dict[str, Any]) -> str:
    discriminator = properties.get("path_id") or properties.get("control") or ""
    return "relayx:edge:" + _slug(f"{kind}:{start_id}:{end_id}:{discriminator}")


def _dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {edge["id"]: edge for edge in edges}
    return [by_id[key] for key in sorted(by_id)]


def _path_record(path: RelayPath) -> dict:
    assessment = assess_path(path)
    controls = _path_controls(path)
    return {
        "fingerprint": _path_fingerprint(path),
        "id": path.id,
        "source": path.source,
        "transport": path.transport,
        "target": path.target,
        "target_service": path.target_service,
        "status": path.status.value,
        "score": path.score,
        "impact": path.impact.value,
        "confidence": path.confidence.value,
        "rule_id": assessment.rule_id,
        "decision": assessment.decision,
        "target_family": assessment.target_family,
        "source_capability": str(evidence_value(path, "source_capability", "generic")),
        "control_keys": controls,
        "route_state": str(evidence_value(path, "route_reachability_state", "")),
        "route_risk_level": str(evidence_value(path, "route_risk_level", "")),
        "route_risk_score": evidence_value(path, "route_risk_score", ""),
    }


def _finding_record(finding) -> dict:
    return {
        "fingerprint": _finding_fingerprint(finding),
        "host": finding.host,
        "port": finding.port,
        "protocol": finding.protocol,
        "name": finding.name,
        "status": finding.status.value,
        "confidence": finding.confidence.value,
        "impact": finding.impact.value,
        "summary": finding.summary,
    }


def _path_change(old: RelayPath, new: RelayPath) -> dict:
    old_assessment = assess_path(old)
    new_assessment = assess_path(new)
    changes = []
    change_records = []
    pairs = {
        "status": (old.status.value, new.status.value),
        "score": (old.score, new.score),
        "impact": (old.impact.value, new.impact.value),
        "confidence": (old.confidence.value, new.confidence.value),
        "decision": (old_assessment.decision, new_assessment.decision),
        "response_classification": (
            evidence_value(old, "relayx_response_classification", ""),
            evidence_value(new, "relayx_response_classification", ""),
        ),
        "response_subclassification": (
            evidence_value(old, "relayx_response_subclassification", ""),
            evidence_value(new, "relayx_response_subclassification", ""),
        ),
        "policy_inference": (
            evidence_value(old, "relayx_policy_inference", ""),
            evidence_value(new, "relayx_policy_inference", ""),
        ),
        "oracle_signature": (
            evidence_value(old, "relayx_oracle_signature", ""),
            evidence_value(new, "relayx_oracle_signature", ""),
        ),
        "route_state": (
            evidence_value(old, "route_reachability_state", ""),
            evidence_value(new, "route_reachability_state", ""),
        ),
        "route_risk_level": (
            evidence_value(old, "route_risk_level", ""),
            evidence_value(new, "route_risk_level", ""),
        ),
    }
    for key, (left, right) in pairs.items():
        if left != right:
            changes.append(f"{key}: {left!r} -> {right!r}")
            change_records.append({"field": key, "old": left, "new": right})
    score_delta = round(new.score - old.score, 2)
    return {
        "fingerprint": _path_fingerprint(new),
        "old": _path_record(old),
        "new": _path_record(new),
        "changes": changes,
        "change_records": change_records,
        "score_delta": score_delta,
        "trend": "regressed" if score_delta > 0 else "improved" if score_delta < 0 else "changed",
        "changed": bool(changes),
    }


def _control_trends(old_paths: list[RelayPath], new_paths: list[RelayPath]) -> list[dict[str, Any]]:
    old_by_control = {row["control"]: row for row in control_summary(old_paths)}
    new_by_control = {row["control"]: row for row in control_summary(new_paths)}
    rows: list[dict[str, Any]] = []
    for control in sorted(set(old_by_control) | set(new_by_control)):
        old_row = old_by_control.get(control, {})
        new_row = new_by_control.get(control, {})
        old_score = float(old_row.get("cumulative_score", 0.0))
        new_score = float(new_row.get("cumulative_score", 0.0))
        old_count = int(old_row.get("paths", 0))
        new_count = int(new_row.get("paths", 0))
        score_delta = round(new_score - old_score, 2)
        path_delta = new_count - old_count
        if path_delta > 0 or score_delta > 0:
            trend = "regressed"
        elif path_delta < 0 or score_delta < 0:
            trend = "improved"
        else:
            trend = "unchanged"
        rows.append(
            {
                "control": control,
                "label": CONTROL_LABELS.get(control, control.replace("_", " ").title()),
                "old_paths": old_count,
                "new_paths": new_count,
                "path_delta": path_delta,
                "old_score": round(old_score, 2),
                "new_score": round(new_score, 2),
                "score_delta": score_delta,
                "trend": trend,
                "old_path_ids": old_row.get("path_ids", []),
                "new_path_ids": new_row.get("path_ids", []),
            }
        )
    return rows


def _exposure_trend(
    *,
    old_score: float,
    new_score: float,
    added: list[dict],
    removed: list[dict],
    changed: list[dict],
) -> str:
    added_exposure = [row for row in added if row.get("status") != Status.BLOCKED.value]
    removed_exposure = [row for row in removed if row.get("status") != Status.BLOCKED.value]
    regression = new_score > old_score or bool(added_exposure) or any(row.get("score_delta", 0) > 0 for row in changed)
    improvement = new_score < old_score or bool(removed_exposure) or any(row.get("score_delta", 0) < 0 for row in changed)
    if regression and improvement:
        return "mixed"
    if regression:
        return "regressed"
    if improvement:
        return "improved"
    return "unchanged"


def _path_fingerprint(path: RelayPath) -> str:
    return "|".join([path.source, path.transport, path.target, path.target_service]).lower()


def _finding_fingerprint(finding) -> str:
    return "|".join([finding.host, str(finding.port), finding.protocol, finding.name]).lower()


def _source_id(value: str) -> str:
    return "relayx:source:" + _slug(value)


def _target_id(value: str) -> str:
    return "relayx:target:" + _slug(value)


def _target_service_id(host: str, service: str) -> str:
    return "relayx:target-service:" + _slug(host + ":" + service)


def _finding_id(host: str, protocol: str, port: int, name: str) -> str:
    return "relayx:finding:" + _slug(f"{host}:{protocol}:{port}:{name}")


def _path_id(value: str) -> str:
    return "relayx:path:" + _slug(value)


def _control_id(value: str) -> str:
    return "relayx:control:" + _slug(value)


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_") or "unknown"
