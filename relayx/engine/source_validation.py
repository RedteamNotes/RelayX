from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import uuid4

from ..models import NoiseLevel, SourceAsset
from ..net import tcp_connect
from .opsec_policy import OpsecPolicy, evaluate_source_opsec
from .routes import normalize_route_hops
from .scope import ScopePolicy
from .source import (
    CAPABILITY_SPECS,
    NOISE_RANK,
    SourceCapabilitySpec,
    source_capabilities,
)


@dataclass(slots=True)
class SourceCheckRequest:
    max_noise: NoiseLevel = NoiseLevel.HIGH
    scope: ScopePolicy | None = None
    connect_check: bool = False
    timeout: float = 3.0
    opsec_policy: OpsecPolicy | None = None
    listener_host: str = ""
    callback_host: str = ""


def check_sources(sources: list[SourceAsset], request: SourceCheckRequest) -> dict:
    checks: list[dict] = []
    for source in sorted(sources, key=lambda item: item.host):
        if request.scope and not request.scope.contains(source.host):
            checks.append(_out_of_scope_check(source))
            continue
        specs = source_capabilities(source, max_noise=request.max_noise)
        if not specs:
            checks.append(_no_capability_check(source, request.max_noise))
            continue
        for spec in specs:
            checks.append(_check_capability(source, spec, request))
    return {
        "metadata": {
            "tool": "RelayX",
            "mode": "source_check",
            "source_count": len(sources),
            "check_count": len(checks),
            "connect_check": request.connect_check,
            "max_noise": request.max_noise.value,
        },
        "checks": checks,
        "summary": _summary(checks),
    }


def build_source_plan(
    sources: list[SourceAsset],
    source_host: str,
    capability: str,
    request: SourceCheckRequest | None = None,
) -> dict:
    request = request or SourceCheckRequest()
    source = _find_source(sources, source_host)
    if not source:
        return _source_plan_error(source_host, capability, "source_not_found", "Source asset was not supplied.")
    normalized = _normalize_capability(capability)
    spec = CAPABILITY_SPECS.get(normalized)
    if not spec:
        return _source_plan_error(source.host, capability, "unsupported_capability", "Capability is not known to RelayX.")
    if request.scope and not request.scope.contains(source.host):
        return _source_plan_error(source.host, normalized, "out_of_scope", "Source is outside supplied scope.")
    if not source.capabilities.get(normalized, False) and not _alias_enabled(source, normalized):
        return _source_plan_error(source.host, normalized, "capability_not_enabled", "Source profile does not enable this capability.")
    if NOISE_RANK[spec.noise] > NOISE_RANK[request.max_noise]:
        return _source_plan_error(source.host, normalized, "noise_budget_exceeded", f"Capability noise {spec.noise.value} exceeds max-noise {request.max_noise.value}.")

    opsec_report = _source_opsec_report(source, spec, request, operation="source-plan", network_action="none")
    scope_contract = _scope_contract(
        request.scope,
        source=source.host,
        listener_host=request.listener_host,
        callback_host=request.callback_host,
        callback_required=normalized in CAPABILITY_SPECS and normalized in {
            "webclient",
            "spooler",
            "efsrpc",
            "dfsnm",
            "fsrvp",
            "mssql_outbound",
            "name_resolution",
        },
    )
    plan = {
        "plan_id": f"SP-{uuid4().hex[:12]}",
        "source": source.host,
        "capability": normalized,
        "label": spec.label,
        "source_protocol": spec.source_protocol,
        "noise": spec.noise.value,
        "compatible_target_protocols": sorted(spec.compatible_target_protocols),
        "state": "planned",
        "execution": {
            "supported": False,
            "reason": "RelayX plans and checks source capabilities but does not execute source-side triggers.",
        },
        "preconditions": source_preconditions(source, spec),
        "expected_telemetry": source_expected_telemetry(source, spec),
        "rollback": source_rollback(source, spec),
        "operator_guardrails": source_guardrails(spec),
        "forbidden_actions": forbidden_source_actions(spec),
        "scope_contract": scope_contract,
        "opsec_policy": opsec_report,
        "next_steps": [
            "Use relayx validate for target-only validation.",
            "Collect real lab evidence before enabling any future source-trigger module.",
            "Keep source-trigger execution single-source, single-callback, and explicitly authorized.",
        ],
    }
    if opsec_report["decision"] == "fail":
        plan["state"] = "opsec_blocked"
        plan["execution"]["reason"] = "OPSEC policy blocked this source plan."
    if any(item["state"] == "fail" for item in scope_contract["guardrails"]):
        plan["state"] = "scope_blocked"
        plan["execution"]["reason"] = "Source, listener, or callback planning is outside supplied scope."
    if source.routes:
        plan["routes"] = source.routes
    route_context = _source_route_context(source)
    if route_context["present"]:
        plan["route_context"] = route_context
    if source.tags:
        plan["tags"] = source.tags
    if source.notes:
        plan["notes"] = source.notes
    return plan


def render_source_checks(report: dict) -> str:
    checks = report.get("checks", [])
    if not checks:
        return "No source checks available."
    lines = ["RelayX Source Checks", ""]
    summary = report.get("summary", {})
    if summary:
        lines.append("Summary: " + ", ".join(f"{key}={value}" for key, value in sorted(summary.items())))
        lines.append("")
    for check in checks:
        lines.append(
            f"{check['source']} {check['capability']} state={check['state']} "
            f"noise={check['noise']} active={check['active_performed']}"
        )
        lines.append(f"  reason: {check['reason']}")
        for evidence in check.get("evidence", []):
            lines.append(f"  evidence: {evidence['key']}={evidence['value']!r}")
        for limitation in check.get("limitations", []):
            lines.append(f"  limit: {limitation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def source_checks_to_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def render_source_plan(plan: dict) -> str:
    if plan.get("state") == "error":
        return f"RelayX Source Plan\n\n{plan['source']} {plan['capability']} error={plan['error']}\n  reason: {plan['reason']}"
    lines = [
        "RelayX Source Plan",
        "",
        f"Plan ID    : {plan['plan_id']}",
        f"Source     : {plan['source']}",
        f"Capability : {plan['capability']}",
        f"Noise      : {plan['noise']}",
        f"State      : {plan['state']}",
        f"OPSEC      : {plan.get('opsec_policy', {}).get('policy', {}).get('name', '-')} "
        f"decision={plan.get('opsec_policy', {}).get('decision', '-')}",
        "",
        "Preconditions:",
    ]
    for item in plan["preconditions"]:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Expected Telemetry:")
    for item in plan["expected_telemetry"]:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Rollback:")
    for item in plan["rollback"]:
        lines.append(f"  - {item}")
    lines.append("")
    if plan.get("route_context"):
        route_context = plan["route_context"]
        lines.append("Route Context:")
        if route_context.get("session"):
            lines.append(f"  - session: {route_context['session']}")
        if route_context.get("segment"):
            lines.append(f"  - segment: {route_context['segment']}")
        if route_context.get("subnets"):
            lines.append(f"  - subnets: {', '.join(route_context['subnets'])}")
        if route_context.get("pivot_types"):
            lines.append(f"  - pivots: {', '.join(route_context['pivot_types'])}")
        lines.append("")
    if plan.get("scope_contract"):
        contract = plan["scope_contract"]
        lines.append("Scope Contract:")
        for item in contract.get("guardrails", []):
            lines.append(f"  - {item['key']}: {item['state']} - {item['reason']}")
        lines.append("")
    lines.append("Forbidden Actions:")
    for item in plan["forbidden_actions"]:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append(f"Execution: supported={plan['execution']['supported']} - {plan['execution']['reason']}")
    return "\n".join(lines)


def source_plan_to_json(plan: dict) -> str:
    return json.dumps(plan, indent=2, sort_keys=True)


def source_preconditions(source: SourceAsset, spec: SourceCapabilitySpec) -> list[str]:
    base = [
        "Written authorization includes this exact source host and capability.",
        "A single target/callback and rollback owner are defined before any future active trigger.",
        "Expected telemetry and help-desk/business impact are reviewed with stakeholders.",
    ]
    if source.routes or source.route_hops or source.subnets:
        base.append("Operator route metadata is present and should be verified before validation.")
    if spec.key in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        base.append("RPC exposure is verified with low-noise reachability checks before any protocol-specific validation.")
    if spec.key == "mssql_outbound":
        base.append("SQL privileges, service account context, and egress controls are confirmed in a lab.")
    if spec.key == "name_resolution":
        base.append("Name registration authority, TTL, affected scope, and deletion path are documented.")
    if spec.key == "webclient":
        base.append("WebClient behavior is validated in lab with a single operator-controlled URL.")
    return base


def source_expected_telemetry(source: SourceAsset, spec: SourceCapabilitySpec) -> list[str]:
    telemetry = [
        "RelayX source-check or source-plan artifact.",
        "Operator audit log entry if future active validation is approved.",
    ]
    if spec.key == "webclient":
        telemetry.extend(
            [
                "WebClient service activity on the source if a future trigger is executed.",
                "Outbound HTTP/WebDAV authentication attempt toward the operator-controlled endpoint.",
            ]
        )
    elif spec.key in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        telemetry.extend(
            [
                "RPC service access telemetry on the source if a future trigger is executed.",
                "Outbound NTLM callback from the source to the approved listener.",
            ]
        )
    elif spec.key == "mssql_outbound":
        telemetry.extend(
            [
                "SQL Server audit/default trace entries if a future outbound-auth primitive is executed.",
                "Outbound authentication from SQL Server service account context.",
            ]
        )
    elif spec.key == "name_resolution":
        telemetry.extend(
            [
                "ADIDNS/SPN/name-resolution change logs if a future naming change is approved.",
                "Name query and cleanup evidence within the affected scope.",
            ]
        )
    if source.routes or source.route_hops or source.subnets:
        route_context = _source_route_context(source)
        telemetry.append(
            "Route or pivot context to verify: "
            f"stateful_hops={route_context['hop_count']} pivots={','.join(route_context['pivot_types']) or '-'}."
        )
    return telemetry


def source_rollback(source: SourceAsset, spec: SourceCapabilitySpec) -> list[str]:
    steps = [
        "Preserve source-plan evidence and timestamps.",
        "Stop any operator-controlled listener associated with future validation.",
    ]
    if spec.key == "name_resolution":
        steps.append("Remove any created DNS/SPN/name-resolution record and verify deletion.")
    if spec.key == "mssql_outbound":
        steps.append("Remove any future SQL validation artifact such as jobs, linked-server tests, or procedure traces.")
    if spec.key in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        steps.append("Confirm no future RPC validation process or callback remains active.")
    if spec.key == "webclient":
        steps.append("Confirm the operator-controlled WebDAV URL is no longer reachable after validation.")
    return steps


def _source_route_context(source: SourceAsset) -> dict:
    hops = normalize_route_hops(source)
    pivot_types: list[str] = []
    for hop in hops:
        if hop.kind not in pivot_types:
            pivot_types.append(hop.kind)
    return {
        "present": bool(source.routes or source.route_hops or source.subnets or source.session or source.segment),
        "session": source.session,
        "segment": source.segment,
        "subnets": source.subnets,
        "routes": source.routes,
        "hop_count": len(hops),
        "pivot_types": pivot_types,
        "hops": [hop.to_dict() for hop in hops],
    }


def source_guardrails(spec: SourceCapabilitySpec) -> list[str]:
    return [
        "Do not run broad source-trigger sweeps.",
        "Use one source, one callback, one target path, and one time window.",
        "Record operator, reason, timestamps, and expected telemetry.",
        f"Respect the {spec.noise.value} OPSEC noise rating for this capability.",
    ]


def forbidden_source_actions(spec: SourceCapabilitySpec) -> list[str]:
    actions = [
        "Credential relay execution.",
        "Credential capture or reuse.",
        "Unscoped callback listener operation.",
    ]
    if spec.key == "webclient":
        actions.append("Triggering WebClient/WebDAV authentication.")
    elif spec.key in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        actions.append("Issuing RPC coercion calls.")
    elif spec.key == "mssql_outbound":
        actions.append("Executing SQL outbound-auth primitives.")
    elif spec.key == "name_resolution":
        actions.append("Creating or modifying ADIDNS/SPN/name-resolution records.")
    return actions


def _check_capability(source: SourceAsset, spec: SourceCapabilitySpec, request: SourceCheckRequest) -> dict:
    network_action = "tcp_connect_check" if request.connect_check else "none"
    opsec_report = _source_opsec_report(source, spec, request, operation="source-check", network_action=network_action)
    if opsec_report["decision"] == "fail":
        return {
            "source": source.host,
            "capability": spec.key,
            "label": spec.label,
            "noise": spec.noise.value,
            "state": "opsec_blocked",
            "reason": "OPSEC policy blocked this source capability check.",
            "active_performed": False,
            "evidence": [],
            "limitations": ["Review the OPSEC policy outcome before planning source validation."],
            "expected_telemetry": source_expected_telemetry(source, spec),
            "rollback": source_rollback(source, spec),
            "forbidden_actions": forbidden_source_actions(spec),
            "opsec_policy": opsec_report,
        }
    evidence: list[dict] = [
        {"key": "source_profile_capability", "value": spec.key},
        {"key": "source_protocol", "value": spec.source_protocol},
    ]
    active_performed = False
    limitations = [
        "RelayX does not execute the source-side trigger for this capability.",
    ]
    if not request.connect_check:
        state = "modeled"
        reason = "Capability is present in the supplied source profile; no reachability check was requested."
    elif spec.key in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        active_performed = True
        ports = _check_ports(source.host, [135, 445], request.timeout)
        evidence.append({"key": "tcp_reachability", "value": ports})
        if any(item["open"] for item in ports):
            state = "network_surface_observed"
            reason = "RPC/SMB TCP reachability was observed. No RPC method call was made."
        else:
            state = "network_surface_not_observed"
            reason = "RPC/SMB TCP reachability was not observed."
    elif spec.key == "mssql_outbound":
        active_performed = True
        ports = _check_ports(source.host, [1433], request.timeout)
        evidence.append({"key": "tcp_reachability", "value": ports})
        if any(item["open"] for item in ports):
            state = "network_surface_observed"
            reason = "MSSQL TCP reachability was observed. No SQL command was executed."
        else:
            state = "network_surface_not_observed"
            reason = "MSSQL TCP reachability was not observed."
    else:
        state = "plan_only"
        reason = "This capability cannot be safely verified by remote TCP reachability alone."
        limitations.append("Use lab validation and operator-owned telemetry before any future active trigger.")
    return {
        "source": source.host,
        "capability": spec.key,
        "label": spec.label,
        "noise": spec.noise.value,
        "state": state,
        "reason": reason,
        "active_performed": active_performed,
        "evidence": evidence,
        "limitations": limitations,
        "expected_telemetry": source_expected_telemetry(source, spec),
        "rollback": source_rollback(source, spec),
        "forbidden_actions": forbidden_source_actions(spec),
        "opsec_policy": opsec_report,
    }


def _check_ports(host: str, ports: list[int], timeout: float) -> list[dict]:
    rows = []
    for port in ports:
        result = tcp_connect(host, port, timeout=timeout)
        rows.append({"port": port, "open": result.open, "error": result.error})
    return rows


def _source_opsec_report(
    source: SourceAsset,
    spec: SourceCapabilitySpec,
    request: SourceCheckRequest,
    *,
    operation: str,
    network_action: str,
) -> dict:
    return evaluate_source_opsec(
        source,
        policy=request.opsec_policy,
        operation=operation,
        capability=spec.key,
        requested_noise=spec.noise,
        max_noise=request.max_noise,
        scope=request.scope,
        connect_check=request.connect_check,
        network_action=network_action,
        expected_telemetry=source_expected_telemetry(source, spec),
        rollback=source_rollback(source, spec),
        listener_host=request.listener_host,
        callback_host=request.callback_host,
    )


def _out_of_scope_check(source: SourceAsset) -> dict:
    return {
        "source": source.host,
        "capability": "scope",
        "label": "Scope guardrail",
        "noise": "passive",
        "state": "out_of_scope",
        "reason": "Source is outside supplied scope.",
        "active_performed": False,
        "evidence": [],
        "limitations": ["Add the source to scope or remove it from the source profile."],
        "expected_telemetry": [],
        "rollback": [],
        "forbidden_actions": [],
    }


def _no_capability_check(source: SourceAsset, max_noise: NoiseLevel) -> dict:
    return {
        "source": source.host,
        "capability": "none",
        "label": "No modeled source capability",
        "noise": "passive",
        "state": "no_capability",
        "reason": f"No enabled capability is available within max-noise {max_noise.value}.",
        "active_performed": False,
        "evidence": [],
        "limitations": ["Adjust the source profile or noise budget if this is unexpected."],
        "expected_telemetry": [],
        "rollback": [],
        "forbidden_actions": [],
    }


def _summary(checks: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for check in checks:
        state = str(check["state"])
        counts[state] = counts.get(state, 0) + 1
    return counts


def _find_source(sources: list[SourceAsset], source_host: str) -> SourceAsset | None:
    wanted = source_host.lower()
    for source in sources:
        if source.host.lower() == wanted:
            return source
    return None


def _normalize_capability(value: str) -> str:
    aliases = {
        "webdav": "webclient",
        "adidns": "name_resolution",
        "ghost_spn": "name_resolution",
    }
    return aliases.get(value.strip().lower(), value.strip().lower())


def _alias_enabled(source: SourceAsset, normalized: str) -> bool:
    if normalized == "webclient" and source.capabilities.get("webdav", False):
        return True
    if normalized == "name_resolution":
        return source.capabilities.get("adidns", False) or source.capabilities.get("ghost_spn", False)
    return False


def _scope_contract(
    scope: ScopePolicy | None,
    *,
    source: str,
    listener_host: str,
    callback_host: str,
    callback_required: bool,
) -> dict:
    guardrails = []
    scope_present = scope is not None and not scope.empty
    if scope_present:
        guardrails.append(
            _scope_guardrail(
                "scope_source",
                bool(scope and scope.contains(source)),
                "Source is inside supplied scope.",
                "Source is outside supplied scope.",
            )
        )
    else:
        guardrails.append(
            {
                "key": "scope_present",
                "state": "warn",
                "reason": "No explicit scope was supplied for source-trigger planning.",
            }
        )
    if listener_host:
        guardrails.append(
            _scope_guardrail(
                "scope_listener",
                bool(scope and scope.contains(listener_host)),
                "Listener host is inside supplied scope.",
                "Listener host is outside supplied scope.",
            )
        )
    else:
        guardrails.append(
            {
                "key": "scope_listener",
                "state": "warn",
                "reason": "No listener host was declared; future listener planning must supply one.",
            }
        )
    if callback_host:
        guardrails.append(
            _scope_guardrail(
                "scope_callback",
                bool(scope and scope.contains(callback_host)),
                "Callback host is inside supplied scope.",
                "Callback host is outside supplied scope.",
            )
        )
    elif callback_required:
        guardrails.append(
            {
                "key": "scope_callback",
                "state": "warn",
                "reason": "No callback host was declared for this future-active source capability.",
            }
        )
    return {
        "scope_present": scope_present,
        "source": source,
        "listener_host": listener_host,
        "callback_host": callback_host,
        "callback_required": callback_required,
        "guardrails": guardrails,
    }


def _scope_guardrail(key: str, ok: bool, pass_reason: str, fail_reason: str) -> dict:
    return {
        "key": key,
        "state": "pass" if ok else "fail",
        "reason": pass_reason if ok else fail_reason,
    }


def _source_plan_error(source: str, capability: str, error: str, reason: str) -> dict:
    return {
        "source": source,
        "capability": capability,
        "state": "error",
        "error": error,
        "reason": reason,
        "execution": {
            "supported": False,
            "reason": "RelayX cannot build a source plan until this error is resolved.",
        },
    }
