from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter

from .engine.calculus import annotate_paths, assess_path
from .engine.controls import CONTROL_LABELS, control_summary
from .engine.evidence import evidence_value
from .engine.opsec import build_dry_run_plan
from .engine.path import remediation_counts
from .engine.source import source_capabilities
from .models import Impact, ScanResult, Status, to_plain


def render_summary(result: ScanResult) -> str:
    statuses = Counter(f.status.value for f in result.findings)
    path_statuses = Counter(p.status.value for p in result.paths)
    impacts = Counter(p.impact.value for p in result.paths)
    lines = [
        "RelayX Summary",
        "",
        f"Targets: {result.metadata.target_count}",
        f"Sources: {result.metadata.source_count}",
        f"Findings: {len(result.findings)}",
        f"Paths: {len(result.paths)}",
        "",
        "Finding Status:",
    ]
    for status, count in sorted(statuses.items()):
        lines.append(f"  {status}: {count}")
    lines.extend(["", "Path Status:"])
    for status, count in sorted(path_statuses.items()):
        lines.append(f"  {status}: {count}")
    lines.extend(["", "Path Impact:"])
    for impact, count in sorted(impacts.items()):
        lines.append(f"  {impact}: {count}")
    return "\n".join(lines)


def render_sources(result: ScanResult) -> str:
    if not result.sources:
        return "No source assets supplied."
    lines = ["RelayX Sources", ""]
    for source in sorted(result.sources, key=lambda item: item.host):
        caps = source_capabilities(source)
        cap_labels = ", ".join(f"{cap.key}({cap.noise.value})" for cap in caps) or "none"
        lines.append(f"{source.host}")
        lines.append(f"  capabilities: {cap_labels}")
        if source.tags:
            lines.append(f"  tags: {', '.join(source.tags)}")
        if source.session:
            lines.append(f"  session: {source.session}")
        if source.segment:
            lines.append(f"  segment: {source.segment}")
        if source.subnets:
            lines.append(f"  subnets: {', '.join(source.subnets)}")
        if source.routes:
            lines.append(f"  routes: {', '.join(source.routes)}")
        if source.route_hops:
            lines.append(f"  route_hops: {len(source.route_hops)} structured hop(s)")
        if source.notes:
            lines.append(f"  notes: {'; '.join(source.notes)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_paths(result: ScanResult, include_blocked: bool = False) -> str:
    paths = result.paths if include_blocked else [p for p in result.paths if p.status != Status.BLOCKED]
    if not paths:
        return "No paths to display."
    lines: list[str] = []
    for path in paths:
        lines.append(
            f"{path.id} [{path.status.value.upper()}] score={path.score} impact={path.impact.value} "
            f"{path.source} -> {path.transport} -> {path.target} ({path.target_service})"
        )
        lines.append(f"  {path.summary}")
        if path.blockers:
            lines.append(f"  Blockers: {'; '.join(path.blockers)}")
        if path.fixes:
            lines.append(f"  Fixes: {'; '.join(path.fixes)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_matrix(result: ScanResult) -> str:
    if not result.findings:
        return "No findings available."
    hosts = sorted({finding.host for finding in result.findings})
    protocols = ["smb", "ldap", "ldaps", "http", "https", "mssql"]
    rows: list[list[str]] = []
    for host in hosts:
        row = [host]
        host_findings = [f for f in result.findings if f.host == host]
        for protocol in protocols:
            matches = [f for f in host_findings if f.protocol == protocol]
            if not matches:
                row.append("-")
                continue
            priority = {
                Status.RELAYABLE: 5,
                Status.CANDIDATE: 4,
                Status.UNKNOWN: 3,
                Status.BLOCKED: 2,
                Status.ERROR: 1,
            }
            best = sorted(matches, key=lambda f: priority[f.status], reverse=True)[0]
            row.append(best.status.value)
        rows.append(row)

    widths = [max(len(row[i]) for row in rows + [["host", *protocols]]) for i in range(len(protocols) + 1)]
    lines = [_format_row(["host", *protocols], widths)]
    lines.append(_format_row(["-" * width for width in widths], widths))
    for row in rows:
        lines.append(_format_row(row, widths))
    return "\n".join(lines)


def _format_row(values: list[str], widths: list[int]) -> str:
    return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values))


def render_plan(result: ScanResult, path_id: str) -> str:
    matches = [path for path in result.paths if path.id == path_id]
    if not matches:
        return f"No path matched {path_id!r}."
    path = matches[0]
    plan = build_dry_run_plan(path)
    lines = [
        f"RelayX Plan: {path.id}",
        "",
        f"Status      : {path.status.value}",
        f"Decision    : {plan['decision']}",
        f"Score       : {path.score}",
        f"Impact      : {path.impact.value}",
        f"Confidence  : {path.confidence.value}",
        f"Source      : {path.source}",
        f"Transport   : {path.transport}",
        f"Target      : {path.target}",
        f"Service     : {path.target_service}",
        f"Rule        : {plan['rule_id']}",
        f"Noise       : {plan['noise']}",
        "",
        "Summary:",
        f"  {path.summary}",
        "",
        "OPSEC Guardrails:",
        "  - Confirm written authorization and exact scope before active validation.",
        "  - Prefer one-path validation over broad coercion or broad relay listeners.",
        "  - Use dry-run/readiness evidence first; escalate only when blockers are understood.",
        "  - Record timestamps, source host, target host, protocol, and operator intent.",
        "  - Prepare rollback and service restoration steps before execution.",
    ]
    if path.opsec_notes:
        lines.append("")
        lines.append("Observed OPSEC Notes:")
        for note in path.opsec_notes:
            lines.append(f"  - {note}")
    if path.blockers:
        lines.append("")
        lines.append("Blockers / Unknowns:")
        for blocker in path.blockers:
            lines.append(f"  - {blocker}")
    if plan["preconditions"]:
        lines.append("")
        lines.append("Preconditions:")
        for precondition in plan["preconditions"]:
            lines.append(f"  - {precondition}")
    if plan["hardening_gates"]:
        lines.append("")
        lines.append("Hardening Gates:")
        for gate in plan["hardening_gates"]:
            lines.append(f"  - {gate['key']}: {gate['state']} ({gate['confidence']}) - {gate['reason']}")
    if plan["expected_telemetry"]:
        lines.append("")
        lines.append("Expected Telemetry:")
        for item in plan["expected_telemetry"]:
            lines.append(f"  - {item}")
    if plan["rollback"]:
        lines.append("")
        lines.append("Rollback:")
        for item in plan["rollback"]:
            lines.append(f"  - {item}")
    if path.evidence:
        lines.append("")
        lines.append("Evidence:")
        for evidence in path.evidence:
            lines.append(
                f"  - {evidence.key}: {evidence.value!r} "
                f"({evidence.type.value}/{evidence.confidence.value})"
            )
    if path.fixes:
        lines.append("")
        lines.append("Remediation if Confirmed:")
        for fix in path.fixes:
            lines.append(f"  - {fix}")
    lines.extend(
        [
            "",
            "Execution:",
            "  RelayX dry-run plans do not execute relay operations. Execution requires",
            "  an explicit scoped plan, confirmation, audit logging, and validated modules.",
        ]
    )
    return "\n".join(lines)


def render_plan_json(result: ScanResult, path_id: str) -> str:
    matches = [path for path in result.paths if path.id == path_id]
    if not matches:
        return json.dumps({"error": f"No path matched {path_id!r}."}, indent=2, sort_keys=True)
    return json.dumps(build_dry_run_plan(matches[0]), indent=2, sort_keys=True)


def render_calculus(result: ScanResult) -> str:
    _ensure_calculus_annotations(result)
    if not result.paths:
        return "No paths available."
    lines = ["RelayX Calculus", ""]
    for path in result.paths:
        assessment = assess_path(path)
        lines.append(
            f"{path.id} {assessment.rule_id} decision={assessment.decision} "
            f"family={assessment.target_family} score={path.score}"
        )
        for gate in assessment.gates:
            lines.append(f"  gate {gate.key}: {gate.state} ({gate.confidence.value}) - {gate.reason}")
        if assessment.controls:
            lines.append(f"  controls: {', '.join(assessment.controls)}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_controls(result: ScanResult) -> str:
    _ensure_calculus_annotations(result)
    rows = control_summary(result.paths)
    if not rows:
        return "No control mappings available."
    lines = ["RelayX Control Priorities", ""]
    for index, row in enumerate(rows, start=1):
        lines.append(f"{index}. {row['label']} ({row['control']})")
        lines.append(
            f"   paths={row['paths']} score={row['cumulative_score']} "
            f"max_impact={row['max_impact']} ids={', '.join(row['path_ids'])}"
        )
    return "\n".join(lines)


def render_explain(result: ScanResult, query: str) -> str:
    matching_paths = [p for p in result.paths if p.id == query or p.target == query or p.source == query]
    matching_findings = [f for f in result.findings if f.host == query]
    if not matching_paths and not matching_findings:
        return f"No findings or paths matched {query!r}."
    lines: list[str] = [f"RelayX Explain: {query}", ""]
    if matching_findings:
        lines.append("Findings:")
        for finding in matching_findings:
            lines.append(
                f"- {finding.protocol}/{finding.port} {finding.name}: "
                f"{finding.status.value} ({finding.confidence.value})"
            )
            lines.append(f"  {finding.summary}")
            for blocker in finding.blockers:
                lines.append(f"  blocker: {blocker}")
    if matching_paths:
        lines.append("")
        lines.append("Paths:")
        for path in matching_paths:
            lines.append(
                f"- {path.id}: {path.status.value} score={path.score} "
                f"{path.source} -> {path.transport} -> {path.target_service}"
            )
            lines.append(f"  {path.summary}")
            for evidence in path.evidence:
                lines.append(
                    f"  evidence: {evidence.key}={evidence.value!r} "
                    f"({evidence.type.value}/{evidence.confidence.value})"
                )
            for blocker in path.blockers:
                lines.append(f"  blocker: {blocker}")
            for fix in path.fixes:
                lines.append(f"  fix: {fix}")
    return "\n".join(lines)


def _ensure_calculus_annotations(result: ScanResult) -> None:
    if any(evidence_value(path, "relayx_rule_id") is None for path in result.paths):
        annotate_paths(result.paths)


def render_fixes(result: ScanResult, top: int = 10) -> str:
    rows = remediation_counts(result.paths)[:top]
    if not rows:
        return "No remediation items available."
    lines = ["RelayX Remediation Priorities", ""]
    for index, (fix, count, score) in enumerate(rows, start=1):
        lines.append(f"{index}. {fix}")
        lines.append(f"   cuts_paths={count} cumulative_score={score}")
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# RelayX Report",
        "",
        "## Summary",
        "",
        "```text",
        render_summary(result),
        "```",
        "",
        "## Ranked Paths",
        "",
    ]
    for path in result.paths:
        lines.append(f"### {path.id}: {path.target_service} on {path.target}")
        lines.append("")
        lines.append(f"- Status: `{path.status.value}`")
        lines.append(f"- Score: `{path.score}`")
        lines.append(f"- Impact: `{path.impact.value}`")
        lines.append(f"- Transport: `{path.transport}`")
        lines.append(f"- Summary: {path.summary}")
        if path.blockers:
            lines.append(f"- Blockers: {'; '.join(path.blockers)}")
        if path.fixes:
            lines.append(f"- Fixes: {'; '.join(path.fixes)}")
        lines.append("")
    lines.extend(["## Controls", "", render_controls(result), "", "## Remediation", "", render_fixes(result)])
    return "\n".join(lines)


def render_html(result: ScanResult) -> str:
    path_rows = []
    for path in result.paths:
        assessment = assess_path(path)
        controls = _path_controls(path)
        source_capability = str(evidence_value(path, "source_capability", "generic"))
        status_class = "status-" + html.escape(path.status.value)
        path_rows.append(
            f'<tr data-status="{html.escape(path.status.value)}" '
            f'data-severity="{html.escape(path.impact.value)}" '
            f'data-protocol="{html.escape(_path_protocol(path))}" '
            f'data-source-capability="{html.escape(source_capability)}" '
            f'data-target-family="{html.escape(assessment.target_family)}" '
            f'data-controls="{html.escape(" ".join(controls))}">'
            f"<td>{html.escape(path.id)}</td>"
            f'<td><span class="pill {status_class}">{html.escape(path.status.value)}</span></td>'
            f"<td>{path.score}</td>"
            f"<td>{html.escape(path.impact.value)}</td>"
            f"<td>{html.escape(path.source)}</td>"
            f"<td>{html.escape(path.transport)}</td>"
            f"<td>{html.escape(path.target)}</td>"
            f"<td>{html.escape(path.target_service)}</td>"
            f"<td>{html.escape(assessment.target_family)}</td>"
            f"<td>{html.escape(source_capability)}</td>"
            f"<td>{html.escape(', '.join(controls))}</td>"
            f"<td>{html.escape(path.summary)}</td>"
            "</tr>"
        )
    fixes = remediation_counts(result.paths)
    fix_items = "\n".join(
        f"<li>{html.escape(fix)} <code>paths={count}</code> <code>score={score}</code></li>"
        for fix, count, score in fixes
    )
    path_statuses = Counter(path.status.value for path in result.paths)
    status_cards = "\n".join(
        f'<div class="metric"><span>{html.escape(status)}</span><strong>{count}</strong></div>'
        for status, count in sorted(path_statuses.items())
    )
    filter_options = _html_filter_options(result)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RelayX Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #17202a; }}
    .metrics {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }}
    .metric {{ border: 1px solid #d5d8dc; border-radius: 6px; padding: 10px 12px; min-width: 120px; background: #fbfcfc; }}
    .metric span {{ display: block; color: #566573; font-size: 12px; text-transform: uppercase; }}
    .metric strong {{ font-size: 22px; }}
    .toolbar {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin: 16px 0; }}
    .toolbar label {{ display: grid; gap: 4px; color: #566573; font-size: 12px; text-transform: uppercase; }}
    .toolbar input, .toolbar select {{ padding: 9px 11px; border: 1px solid #aeb6bf; border-radius: 6px; background: #fff; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
    th, td {{ border: 1px solid #d5d8dc; padding: 8px; vertical-align: top; }}
    th {{ background: #f4f6f7; text-align: left; }}
    tr.hidden {{ display: none; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 12px; font-weight: 600; }}
    .status-candidate, .status-relayable {{ background: #fff3cd; color: #7d5100; }}
    .status-blocked {{ background: #d5f5e3; color: #145a32; }}
    .status-unknown {{ background: #eaf2f8; color: #1b4f72; }}
    .status-error {{ background: #fadbd8; color: #78281f; }}
    code {{ background: #f4f6f7; padding: 2px 4px; border-radius: 4px; }}
    pre {{ background: #17202a; color: #f8f9f9; padding: 16px; overflow: auto; }}
  </style>
</head>
<body>
  <h1>RelayX Report</h1>
  <p><strong>An OPSEC-aware NTLM relay exposure assessment, lab-calibrated validation, and controlled execution orchestration tool for authorized red teaming.</strong></p>
  <h2>Summary</h2>
  <div class="metrics">
    <div class="metric"><span>targets</span><strong>{result.metadata.target_count}</strong></div>
    <div class="metric"><span>sources</span><strong>{result.metadata.source_count}</strong></div>
    <div class="metric"><span>findings</span><strong>{len(result.findings)}</strong></div>
    <div class="metric"><span>paths</span><strong>{len(result.paths)}</strong></div>
    {status_cards}
  </div>
  <pre>{html.escape(render_summary(result))}</pre>
  <h2>Ranked Paths</h2>
  <div class="toolbar">
    <label>Search<input id="pathFilter" type="search" placeholder="source, target, service, summary"></label>
    <label>Status<select id="statusFilter"><option value="">All</option>{filter_options['status']}</select></label>
    <label>Severity<select id="severityFilter"><option value="">All</option>{filter_options['severity']}</select></label>
    <label>Protocol<select id="protocolFilter"><option value="">All</option>{filter_options['protocol']}</select></label>
    <label>Source Capability<select id="sourceCapabilityFilter"><option value="">All</option>{filter_options['source_capability']}</select></label>
    <label>Target Family<select id="targetFamilyFilter"><option value="">All</option>{filter_options['target_family']}</select></label>
    <label>Defensive Control<select id="controlFilter"><option value="">All</option>{filter_options['control']}</select></label>
  </div>
  <p><strong id="visibleCount">{len(result.paths)}</strong> of <strong>{len(result.paths)}</strong> paths visible</p>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Status</th><th>Score</th><th>Impact</th><th>Source</th>
        <th>Transport</th><th>Target</th><th>Service</th><th>Target Family</th>
        <th>Source Capability</th><th>Controls</th><th>Summary</th>
      </tr>
    </thead>
    <tbody>
      {''.join(path_rows)}
    </tbody>
  </table>
  <h2>Remediation Priorities</h2>
  <ol>{fix_items}</ol>
  <script>
    const filter = document.getElementById('pathFilter');
    const visibleCount = document.getElementById('visibleCount');
    const selects = {{
      status: document.getElementById('statusFilter'),
      severity: document.getElementById('severityFilter'),
      protocol: document.getElementById('protocolFilter'),
      sourceCapability: document.getElementById('sourceCapabilityFilter'),
      targetFamily: document.getElementById('targetFamilyFilter'),
      control: document.getElementById('controlFilter'),
    }};
    const rows = Array.from(document.querySelectorAll('tbody tr'));
    function applyFilters() {{
      const query = filter.value.toLowerCase();
      let visible = 0;
      rows.forEach((row) => {{
        const matchesQuery = !query || row.innerText.toLowerCase().includes(query);
        const matchesStatus = !selects.status.value || row.dataset.status === selects.status.value;
        const matchesSeverity = !selects.severity.value || row.dataset.severity === selects.severity.value;
        const matchesProtocol = !selects.protocol.value || row.dataset.protocol === selects.protocol.value;
        const matchesSourceCapability = !selects.sourceCapability.value || row.dataset.sourceCapability === selects.sourceCapability.value;
        const matchesTargetFamily = !selects.targetFamily.value || row.dataset.targetFamily === selects.targetFamily.value;
        const matchesControl = !selects.control.value || row.dataset.controls.split(' ').includes(selects.control.value);
        const show = matchesQuery && matchesStatus && matchesSeverity && matchesProtocol && matchesSourceCapability && matchesTargetFamily && matchesControl;
        row.classList.toggle('hidden', !show);
        if (show) visible += 1;
      }});
      visibleCount.textContent = String(visible);
    }}
    filter.addEventListener('input', applyFilters);
    Object.values(selects).forEach((select) => select.addEventListener('change', applyFilters));
  </script>
</body>
</html>
"""


def _html_filter_options(result: ScanResult) -> dict[str, str]:
    values = {
        "status": sorted({path.status.value for path in result.paths}),
        "severity": sorted({path.impact.value for path in result.paths}),
        "protocol": sorted({_path_protocol(path) for path in result.paths}),
        "source_capability": sorted({str(evidence_value(path, "source_capability", "generic")) for path in result.paths}),
        "target_family": sorted({assess_path(path).target_family for path in result.paths}),
        "control": sorted({control for path in result.paths for control in _path_controls(path)}),
    }
    return {
        key: "\n".join(
            f'<option value="{html.escape(value)}">{html.escape(_filter_label(key, value))}</option>'
            for value in values[key]
            if value
        )
        for key in values
    }


def _filter_label(key: str, value: str) -> str:
    if key == "control":
        return CONTROL_LABELS.get(value, value.replace("_", " ").title())
    return value


def _path_controls(path) -> list[str]:
    raw = evidence_value(path, "relayx_controls", []) or []
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list | tuple | set):
        values = [str(item) for item in raw]
    else:
        values = [str(raw)]
    return sorted({value.strip() for value in values if value and value.strip()})


def _path_protocol(path) -> str:
    service = path.target_service.split("/", 1)[0].strip().lower()
    if service:
        return service
    return path.transport.split("/", 1)[0].strip().lower()


def render_mermaid(result: ScanResult) -> str:
    lines = [
        "flowchart LR",
        "  classDef relayable fill:#fff3cd,stroke:#d68910,color:#4d3300",
        "  classDef blocked fill:#d5f5e3,stroke:#229954,color:#145a32",
        "  classDef unknown fill:#eaf2f8,stroke:#3498db,color:#1b4f72",
    ]
    for path in result.paths:
        source_id = _node_id(f"source_{path.id}")
        target_id = _node_id(f"target_{path.id}")
        label = f"{path.transport}\\n{path.status.value}/{path.impact.value}"
        lines.append(f'  {source_id}["{_escape_mermaid(path.source)}"] -->|"{_escape_mermaid(label)}"| {target_id}["{_escape_mermaid(path.target_service + " @ " + path.target)}"]')
        class_name = "blocked" if path.status == Status.BLOCKED else "relayable" if path.status in {Status.CANDIDATE, Status.RELAYABLE} else "unknown"
        lines.append(f"  class {target_id} {class_name}")
    return "\n".join(lines)


def _node_id(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value)


def _escape_mermaid(value: str) -> str:
    return value.replace('"', "'")


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "status", "score", "impact", "source", "transport", "target", "target_service", "summary"])
    for path in result.paths:
        writer.writerow(
            [
                path.id,
                path.status.value,
                path.score,
                path.impact.value,
                path.source,
                path.transport,
                path.target,
                path.target_service,
                path.summary,
            ]
        )
    return buf.getvalue()


def render_json(result: ScanResult) -> str:
    return json.dumps(to_plain(result), indent=2, sort_keys=True)


def render_report(result: ScanResult, fmt: str) -> str:
    normalized = fmt.lower()
    if normalized == "json":
        return render_json(result)
    if normalized in {"md", "markdown"}:
        return render_markdown(result)
    if normalized == "html":
        return render_html(result)
    if normalized in {"mmd", "mermaid"}:
        return render_mermaid(result)
    if normalized == "csv":
        return render_csv(result)
    raise ValueError(f"unsupported report format: {fmt}")
