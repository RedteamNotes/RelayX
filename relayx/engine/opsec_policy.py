from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import NoiseLevel, RelayPath, SourceAsset
from .calculus import assess_path
from .evidence import evidence_value
from .risk import estimate_noise
from .scope import ScopePolicy
from .source import NOISE_RANK


POLICY_ENGINE_VERSION = 1
OPSEC_DECISIONS = {"pass", "warn", "fail"}
ABSTRACT_SOURCES = {
    "external_or_internal_ntlm_source",
    "webdav_or_http_ntlm_source",
    "mssql_or_coercible_ntlm_source",
}
SOURCE_TRIGGER_CAPABILITIES = {
    "webclient",
    "spooler",
    "efsrpc",
    "dfsnm",
    "fsrvp",
    "mssql_outbound",
    "name_resolution",
}


@dataclass(frozen=True, slots=True)
class OpsecPolicy:
    name: str = "standard"
    description: str = "Standard RelayX OPSEC policy."
    max_noise: NoiseLevel = NoiseLevel.HIGH
    max_timebox_seconds: int = 900
    require_scope_for_armed: bool = False
    require_scope_for_confirmed: bool = False
    require_scope_for_source_plan: bool = False
    require_scope_for_connect_check: bool = False
    require_scope_for_listener: bool = False
    require_scope_for_callback: bool = False
    require_confirm_for_confirmed: bool = True
    require_operator_for_confirmed: bool = True
    require_reason_for_confirmed: bool = True
    require_audit_for_confirmed: bool = True
    allow_auth_validation: bool = True
    require_reprobe_for_auth_validation: bool = True
    allow_source_trigger_execution: bool = False
    allow_credential_capture: bool = False
    allow_credential_forwarding: bool = False
    allow_listener: bool = False
    allowed_network_actions: tuple[str, ...] = (
        "none",
        "target_reprobe",
        "tcp_connect_check",
        "offline_audit_record",
    )
    blocked_source_capabilities: tuple[str, ...] = ()
    blocked_target_families: tuple[str, ...] = ()
    allowed_target_families: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": POLICY_ENGINE_VERSION,
            "max_noise": self.max_noise.value,
            "max_timebox_seconds": self.max_timebox_seconds,
            "require_scope_for_armed": self.require_scope_for_armed,
            "require_scope_for_confirmed": self.require_scope_for_confirmed,
            "require_scope_for_source_plan": self.require_scope_for_source_plan,
            "require_scope_for_connect_check": self.require_scope_for_connect_check,
            "require_scope_for_listener": self.require_scope_for_listener,
            "require_scope_for_callback": self.require_scope_for_callback,
            "require_confirm_for_confirmed": self.require_confirm_for_confirmed,
            "require_operator_for_confirmed": self.require_operator_for_confirmed,
            "require_reason_for_confirmed": self.require_reason_for_confirmed,
            "require_audit_for_confirmed": self.require_audit_for_confirmed,
            "allow_auth_validation": self.allow_auth_validation,
            "require_reprobe_for_auth_validation": self.require_reprobe_for_auth_validation,
            "allow_source_trigger_execution": self.allow_source_trigger_execution,
            "allow_credential_capture": self.allow_credential_capture,
            "allow_credential_forwarding": self.allow_credential_forwarding,
            "allow_listener": self.allow_listener,
            "allowed_network_actions": list(self.allowed_network_actions),
            "blocked_source_capabilities": list(self.blocked_source_capabilities),
            "blocked_target_families": list(self.blocked_target_families),
            "allowed_target_families": list(self.allowed_target_families),
            "notes": list(self.notes),
        }


@dataclass(slots=True)
class OpsecContext:
    operation: str
    mode: str = "dry-run"
    requested_noise: NoiseLevel = NoiseLevel.LOW
    max_noise: NoiseLevel = NoiseLevel.HIGH
    scope: ScopePolicy | None = None
    target: str = ""
    source: str = ""
    source_capability: str = "generic"
    target_family: str = ""
    path_status: str = ""
    calculus_decision: str = ""
    timebox_seconds: int = 300
    confirm: bool = False
    operator: str = ""
    reason: str = ""
    audit_log: str = ""
    auth_validation: bool = False
    reprobe: bool = False
    connect_check: bool = False
    network_action: str = "none"
    module_key: str = ""
    module_supported: bool = False
    module_forbidden_actions: tuple[str, ...] = ()
    source_trigger_required: bool = False
    expected_telemetry: tuple[str, ...] = ()
    rollback: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "mode": self.mode,
            "requested_noise": self.requested_noise.value,
            "max_noise": self.max_noise.value,
            "scope_present": self.scope is not None and not self.scope.empty,
            "target": self.target,
            "source": self.source,
            "source_capability": self.source_capability,
            "target_family": self.target_family,
            "path_status": self.path_status,
            "calculus_decision": self.calculus_decision,
            "timebox_seconds": self.timebox_seconds,
            "confirm": self.confirm,
            "operator_supplied": bool(self.operator.strip()),
            "reason_supplied": bool(self.reason.strip()),
            "audit_log_supplied": bool(self.audit_log.strip()),
            "auth_validation": self.auth_validation,
            "reprobe": self.reprobe,
            "connect_check": self.connect_check,
            "network_action": self.network_action,
            "module_key": self.module_key,
            "module_supported": self.module_supported,
            "module_forbidden_actions": list(self.module_forbidden_actions),
            "source_trigger_required": self.source_trigger_required,
            "expected_telemetry_count": len(self.expected_telemetry),
            "rollback_count": len(self.rollback),
            "extra": self.extra,
        }


def builtin_policies() -> dict[str, OpsecPolicy]:
    return {
        "standard": OpsecPolicy(
            name="standard",
            description=(
                "Default policy for authorized assessments. It enforces credential/listener boundaries, "
                "confirmation context, timebox, and noise budgets without requiring scope for dry-run planning."
            ),
            max_noise=NoiseLevel.HIGH,
            max_timebox_seconds=900,
            notes=(
                "Use --scope for confirmed validation or execution when rules of engagement require explicit scoping.",
            ),
        ),
        "strict": OpsecPolicy(
            name="strict",
            description="Strict OPSEC policy for enterprise exercises and production-adjacent environments.",
            max_noise=NoiseLevel.MEDIUM,
            max_timebox_seconds=300,
            require_scope_for_armed=True,
            require_scope_for_confirmed=True,
            require_scope_for_source_plan=True,
            require_scope_for_connect_check=True,
            require_scope_for_listener=True,
            require_scope_for_callback=True,
            blocked_source_capabilities=("name_resolution",),
            notes=(
                "High-noise source-trigger planning is blocked unless a custom policy permits it.",
                "Confirmed actions require explicit scope, operator, reason, confirmation, and audit log.",
            ),
        ),
        "lab": OpsecPolicy(
            name="lab",
            description="Lab research policy for controlled protocol oracle and calibration work.",
            max_noise=NoiseLevel.HIGH,
            max_timebox_seconds=1200,
            require_scope_for_confirmed=True,
            require_scope_for_source_plan=False,
            notes=(
                "Designed for isolated labs where synthetic authentication validation is authorized.",
                "Source-trigger execution remains blocked by default.",
            ),
        ),
    }


def list_opsec_policies() -> list[dict[str, Any]]:
    return [policy.as_dict() for policy in builtin_policies().values()]


def default_opsec_policy() -> OpsecPolicy:
    return builtin_policies()["standard"]


def load_opsec_policy(value: str | None) -> OpsecPolicy:
    if not value:
        return default_opsec_policy()
    key = value.strip()
    builtins = builtin_policies()
    if key in builtins:
        return builtins[key]
    path = Path(key)
    if not path.exists():
        raise ValueError(f"OPSEC policy does not exist: {value}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"OPSEC policy {path} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"OPSEC policy {path} must contain a JSON object")
    return opsec_policy_from_dict(data)


def opsec_policy_from_dict(data: dict[str, Any]) -> OpsecPolicy:
    def bool_value(key: str, default: bool) -> bool:
        value = data.get(key, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}

    return OpsecPolicy(
        name=str(data.get("name") or "custom"),
        description=str(data.get("description") or "Custom RelayX OPSEC policy."),
        max_noise=NoiseLevel(str(data.get("max_noise") or NoiseLevel.HIGH.value).lower()),
        max_timebox_seconds=int(data.get("max_timebox_seconds", 900)),
        require_scope_for_armed=bool_value("require_scope_for_armed", False),
        require_scope_for_confirmed=bool_value("require_scope_for_confirmed", False),
        require_scope_for_source_plan=bool_value("require_scope_for_source_plan", False),
        require_scope_for_connect_check=bool_value("require_scope_for_connect_check", False),
        require_scope_for_listener=bool_value("require_scope_for_listener", False),
        require_scope_for_callback=bool_value("require_scope_for_callback", False),
        require_confirm_for_confirmed=bool_value("require_confirm_for_confirmed", True),
        require_operator_for_confirmed=bool_value("require_operator_for_confirmed", True),
        require_reason_for_confirmed=bool_value("require_reason_for_confirmed", True),
        require_audit_for_confirmed=bool_value("require_audit_for_confirmed", True),
        allow_auth_validation=bool_value("allow_auth_validation", True),
        require_reprobe_for_auth_validation=bool_value("require_reprobe_for_auth_validation", True),
        allow_source_trigger_execution=bool_value("allow_source_trigger_execution", False),
        allow_credential_capture=bool_value("allow_credential_capture", False),
        allow_credential_forwarding=bool_value("allow_credential_forwarding", False),
        allow_listener=bool_value("allow_listener", False),
        allowed_network_actions=tuple(_string_list(data.get("allowed_network_actions", OpsecPolicy().allowed_network_actions))),
        blocked_source_capabilities=tuple(_string_list(data.get("blocked_source_capabilities", []))),
        blocked_target_families=tuple(_string_list(data.get("blocked_target_families", []))),
        allowed_target_families=tuple(_string_list(data.get("allowed_target_families", []))),
        notes=tuple(_string_list(data.get("notes", []))),
    )


def evaluate_path_opsec(
    path: RelayPath,
    *,
    policy: OpsecPolicy | None = None,
    operation: str,
    mode: str,
    max_noise: NoiseLevel,
    scope: ScopePolicy | None = None,
    timebox_seconds: int = 300,
    confirm: bool = False,
    operator: str = "",
    reason: str = "",
    audit_log: str = "",
    auth_validation: bool = False,
    reprobe: bool = False,
    network_action: str = "none",
    module: dict[str, Any] | None = None,
    expected_telemetry: list[str] | tuple[str, ...] | None = None,
    rollback: list[str] | tuple[str, ...] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assessment = assess_path(path)
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    module_data = module or {}
    context = OpsecContext(
        operation=operation,
        mode=mode,
        requested_noise=estimate_noise(path),
        max_noise=max_noise,
        scope=scope,
        target=path.target,
        source=path.source,
        source_capability=source_capability,
        target_family=assessment.target_family,
        path_status=path.status.value,
        calculus_decision=assessment.decision,
        timebox_seconds=timebox_seconds,
        confirm=confirm,
        operator=operator,
        reason=reason,
        audit_log=audit_log,
        auth_validation=auth_validation,
        reprobe=reprobe,
        network_action=network_action,
        module_key=str(module_data.get("key", "")),
        module_supported=bool(module_data.get("supported", False)),
        module_forbidden_actions=tuple(str(item) for item in module_data.get("forbidden_actions", []) or []),
        source_trigger_required=_requires_source_trigger(path, source_capability),
        expected_telemetry=tuple(expected_telemetry or ()),
        rollback=tuple(rollback or ()),
        extra={
            **dict(extra or {}),
            "module_listener_policy": str(module_data.get("listener_policy") or ""),
        },
    )
    return evaluate_opsec_policy(policy or default_opsec_policy(), context)


def evaluate_source_opsec(
    source: SourceAsset,
    *,
    policy: OpsecPolicy | None = None,
    operation: str,
    capability: str,
    requested_noise: NoiseLevel,
    max_noise: NoiseLevel,
    scope: ScopePolicy | None = None,
    connect_check: bool = False,
    network_action: str = "none",
    expected_telemetry: list[str] | tuple[str, ...] | None = None,
    rollback: list[str] | tuple[str, ...] | None = None,
    listener_host: str = "",
    callback_host: str = "",
) -> dict[str, Any]:
    context = OpsecContext(
        operation=operation,
        mode="dry-run",
        requested_noise=requested_noise,
        max_noise=max_noise,
        scope=scope,
        source=source.host,
        source_capability=capability,
        timebox_seconds=0,
        connect_check=connect_check,
        network_action=network_action,
        source_trigger_required=capability in SOURCE_TRIGGER_CAPABILITIES,
        expected_telemetry=tuple(expected_telemetry or ()),
        rollback=tuple(rollback or ()),
        extra={
            "listener_host": listener_host,
            "callback_host": callback_host,
            "callback_required": capability in SOURCE_TRIGGER_CAPABILITIES,
        },
    )
    return evaluate_opsec_policy(policy or default_opsec_policy(), context)


def evaluate_opsec_policy(policy: OpsecPolicy, context: OpsecContext) -> dict[str, Any]:
    outcomes: list[dict[str, Any]] = []
    _add(outcomes, "policy_loaded", "pass", f"OPSEC policy {policy.name} loaded.")
    _evaluate_noise(policy, context, outcomes)
    _evaluate_scope(policy, context, outcomes)
    _evaluate_confirmation(policy, context, outcomes)
    _evaluate_auth_validation(policy, context, outcomes)
    _evaluate_source_capability(policy, context, outcomes)
    _evaluate_target_family(policy, context, outcomes)
    _evaluate_network_action(policy, context, outcomes)
    _evaluate_timebox(policy, context, outcomes)
    _evaluate_telemetry(policy, context, outcomes)
    decision = _decision(outcomes)
    return {
        "name": "RelayX OPSEC policy evaluation",
        "version": POLICY_ENGINE_VERSION,
        "policy": policy.as_dict(),
        "context": context.as_dict(),
        "decision": decision,
        "state": {"pass": "allowed", "warn": "allowed_with_warnings", "fail": "blocked"}[decision],
        "summary": {
            "pass": sum(1 for row in outcomes if row["state"] == "pass"),
            "warn": sum(1 for row in outcomes if row["state"] == "warn"),
            "fail": sum(1 for row in outcomes if row["state"] == "fail"),
        },
        "outcomes": outcomes,
    }


def opsec_outcomes_as_guardrails(report: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for outcome in report.get("outcomes", []):
        if outcome["key"] == "policy_loaded":
            continue
        rows.append(
            {
                "key": f"opsec_policy:{outcome['key']}",
                "state": outcome["state"],
                "reason": outcome["reason"],
            }
        )
    return rows


def render_opsec_policy(policy: OpsecPolicy) -> str:
    data = policy.as_dict()
    lines = [
        "RelayX OPSEC Policy",
        "",
        f"Name        : {data['name']}",
        f"Max Noise   : {data['max_noise']}",
        f"Timebox Max : {data['max_timebox_seconds']} seconds",
        f"Description : {data['description']}",
        "",
        "Boundaries:",
        f"  auth_validation: {'allowed' if data['allow_auth_validation'] else 'blocked'}",
        f"  source triggers : {'allowed' if data['allow_source_trigger_execution'] else 'blocked'}",
        f"  credential capture: {'allowed' if data['allow_credential_capture'] else 'blocked'}",
        f"  credential forwarding: {'allowed' if data['allow_credential_forwarding'] else 'blocked'}",
        f"  listeners: {'allowed' if data['allow_listener'] else 'blocked'}",
        f"  scope for connect checks: {'required' if data['require_scope_for_connect_check'] else 'not required'}",
        f"  scope for listeners: {'required' if data['require_scope_for_listener'] else 'not required'}",
        f"  scope for callbacks: {'required' if data['require_scope_for_callback'] else 'not required'}",
        "",
        "Allowed Network Actions: " + ", ".join(data["allowed_network_actions"]),
    ]
    if data["blocked_source_capabilities"]:
        lines.append("Blocked Source Capabilities: " + ", ".join(data["blocked_source_capabilities"]))
    if data["notes"]:
        lines.extend(["", "Notes:"])
        for note in data["notes"]:
            lines.append(f"  - {note}")
    return "\n".join(lines)


def render_opsec_policies(policies: list[dict[str, Any]]) -> str:
    lines = ["RelayX OPSEC Policies", ""]
    for policy in policies:
        lines.append(f"- {policy['name']}: max_noise={policy['max_noise']} timebox={policy['max_timebox_seconds']}s")
        lines.append(f"  {policy['description']}")
    return "\n".join(lines)


def render_opsec_evaluation(report: dict[str, Any]) -> str:
    lines = [
        "RelayX OPSEC Policy Evaluation",
        "",
        f"Policy   : {report['policy']['name']}",
        f"Decision : {report['decision']}",
        f"State    : {report['state']}",
        "",
        "Outcomes:",
    ]
    for outcome in report.get("outcomes", []):
        lines.append(f"  - {outcome['key']}: {outcome['state']} - {outcome['reason']}")
    return "\n".join(lines)


def opsec_policy_to_json(policy: OpsecPolicy) -> str:
    return json.dumps(policy.as_dict(), indent=2, sort_keys=True)


def opsec_policies_to_json(policies: list[dict[str, Any]]) -> str:
    return json.dumps({"policies": policies}, indent=2, sort_keys=True)


def opsec_evaluation_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def _evaluate_noise(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    effective = _min_noise(policy.max_noise, context.max_noise)
    ok = NOISE_RANK[context.requested_noise] <= NOISE_RANK[effective]
    _add(
        outcomes,
        "noise_budget",
        "pass" if ok else "fail",
        (
            f"Requested noise {context.requested_noise.value} is within effective ceiling {effective.value}."
            if ok
            else f"Requested noise {context.requested_noise.value} exceeds effective ceiling {effective.value}."
        ),
        evidence={"requested_noise": context.requested_noise.value, "policy_max_noise": policy.max_noise.value, "request_max_noise": context.max_noise.value},
    )


def _evaluate_scope(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    listener_host = _extra_text(context, "listener_host")
    callback_host = _extra_text(context, "callback_host")
    listener_required = bool(context.extra.get("listener_required")) or _extra_text(context, "module_listener_policy") not in {"", "none"}
    callback_required = bool(context.extra.get("callback_required"))
    scope_required = (
        (context.mode == "armed" and policy.require_scope_for_armed)
        or (context.mode == "confirmed" and policy.require_scope_for_confirmed)
        or (context.operation == "source-plan" and policy.require_scope_for_source_plan)
        or (context.connect_check and policy.require_scope_for_connect_check)
        or ((listener_host or listener_required) and policy.require_scope_for_listener)
        or ((callback_host or callback_required) and policy.require_scope_for_callback)
    )
    has_scope = context.scope is not None and not context.scope.empty
    if scope_required and not has_scope:
        _add(outcomes, "scope_required", "fail", "Policy requires explicit scope for this operation and mode.")
        return
    if not has_scope:
        _add(outcomes, "scope", "pass", "No explicit scope is required by this policy for the current operation.")
        return
    if context.target:
        target_in_scope = context.scope.contains(context.target) if context.scope else False
        _add(
            outcomes,
            "scope_target",
            "pass" if target_in_scope else "fail",
            "Target is inside supplied scope." if target_in_scope else "Target is outside supplied scope.",
        )
    if context.source and context.source.lower() not in ABSTRACT_SOURCES:
        source_in_scope = context.scope.contains(context.source) if context.scope else False
        _add(
            outcomes,
            "scope_source",
            "pass" if source_in_scope else "fail",
            "Source is inside supplied scope." if source_in_scope else "Source is outside supplied scope.",
        )
    if listener_host:
        listener_in_scope = context.scope.contains(listener_host) if context.scope else False
        _add(
            outcomes,
            "scope_listener",
            "pass" if listener_in_scope else "fail",
            "Listener host is inside supplied scope." if listener_in_scope else "Listener host is outside supplied scope.",
        )
    elif listener_required and policy.require_scope_for_listener:
        _add(outcomes, "scope_listener", "fail", "Policy requires an explicit listener host for listener-scoped planning.")
    if callback_host:
        callback_in_scope = context.scope.contains(callback_host) if context.scope else False
        _add(
            outcomes,
            "scope_callback",
            "pass" if callback_in_scope else "fail",
            "Callback host is inside supplied scope." if callback_in_scope else "Callback host is outside supplied scope.",
        )
    elif callback_required and policy.require_scope_for_callback:
        _add(outcomes, "scope_callback", "fail", "Policy requires an explicit callback host for callback-scoped planning.")


def _evaluate_confirmation(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    if context.mode != "confirmed":
        _add(outcomes, "confirmed_context", "pass", "Confirmed-mode operator context is not required for this mode.")
        return
    checks = [
        ("confirm", context.confirm, policy.require_confirm_for_confirmed, "Confirmed mode requires explicit confirmation."),
        ("operator", bool(context.operator.strip()), policy.require_operator_for_confirmed, "Confirmed mode requires operator identity."),
        ("reason", bool(context.reason.strip()), policy.require_reason_for_confirmed, "Confirmed mode requires a reason."),
        ("audit_log", bool(context.audit_log.strip()), policy.require_audit_for_confirmed, "Confirmed mode requires an audit log."),
    ]
    for key, ok, required, fail_reason in checks:
        if not required:
            _add(outcomes, f"confirmed_{key}", "pass", f"Policy does not require confirmed {key}.")
            continue
        _add(outcomes, f"confirmed_{key}", "pass" if ok else "fail", f"Confirmed {key} supplied." if ok else fail_reason)


def _evaluate_auth_validation(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    if not context.auth_validation:
        _add(outcomes, "auth_validation", "pass", "Synthetic authentication validation was not requested.")
        return
    if not policy.allow_auth_validation:
        _add(outcomes, "auth_validation", "fail", "Policy blocks synthetic authentication validation.")
        return
    if policy.require_reprobe_for_auth_validation and not (context.mode == "confirmed" and context.confirm and context.reprobe):
        _add(outcomes, "auth_validation_reprobe_gate", "fail", "Synthetic authentication validation requires confirmed mode, confirmation, and target reprobe.")
        return
    _add(outcomes, "auth_validation", "pass", "Synthetic authentication validation is permitted by policy and gated by target reprobe.")


def _evaluate_source_capability(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    capability = context.source_capability
    if capability in policy.blocked_source_capabilities:
        _add(outcomes, "source_capability", "fail", f"Policy blocks source capability {capability}.")
        return
    if context.source_trigger_required and context.network_action == "source_trigger" and not policy.allow_source_trigger_execution:
        _add(outcomes, "source_trigger_execution", "fail", "Policy blocks source-trigger execution.")
        return
    if context.source_trigger_required:
        _add(outcomes, "source_trigger_boundary", "warn", "Path or source depends on a source-trigger surface; policy permits planning but not execution.")
        return
    _add(outcomes, "source_trigger_boundary", "pass", "No source-trigger execution is required.")


def _evaluate_target_family(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    family = context.target_family
    if not family:
        _add(outcomes, "target_family", "pass", "No target family restriction applies.")
        return
    if policy.allowed_target_families and family not in policy.allowed_target_families:
        _add(outcomes, "target_family", "fail", f"Target family {family} is not in the policy allowlist.")
        return
    if family in policy.blocked_target_families:
        _add(outcomes, "target_family", "fail", f"Policy blocks target family {family}.")
        return
    _add(outcomes, "target_family", "pass", f"Target family {family} is permitted by policy.")


def _evaluate_network_action(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    action = context.network_action or "none"
    if action not in policy.allowed_network_actions:
        _add(outcomes, "network_action", "fail", f"Policy does not allow network action {action}.")
    else:
        _add(outcomes, "network_action", "pass", f"Network action {action} is allowed by policy.")
    forbidden = set(context.module_forbidden_actions)
    if "credential_capture" in forbidden or "credential_storage_without_policy" in forbidden:
        _add(
            outcomes,
            "credential_capture_boundary",
            "pass" if not policy.allow_credential_capture else "warn",
            "Credential capture remains blocked by policy."
            if not policy.allow_credential_capture
            else "Policy allows credential capture; verify credential-handling authorization.",
        )
    if "credential_forwarding" in forbidden or "source_trigger_without_plan" in forbidden:
        _add(
            outcomes,
            "credential_forwarding_boundary",
            "pass" if not policy.allow_credential_forwarding else "warn",
            "Credential forwarding remains blocked by policy."
            if not policy.allow_credential_forwarding
            else "Policy allows credential forwarding; verify relay authorization.",
        )
    if "listener_start" in forbidden or "unscoped_listener" in forbidden:
        _add(
            outcomes,
            "listener_boundary",
            "pass" if not policy.allow_listener else "warn",
            "Listener operation remains blocked by policy unless a future module passes explicit guardrails."
            if not policy.allow_listener
            else "Policy allows listener operation; verify listener scope and lifecycle controls.",
        )


def _evaluate_timebox(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    if context.timebox_seconds <= 0:
        _add(outcomes, "timebox", "pass" if context.operation in {"source-check", "source-plan"} else "fail", "No positive timebox is required for this planning-only source operation." if context.operation in {"source-check", "source-plan"} else "Timebox must be positive.")
        return
    ok = context.timebox_seconds <= policy.max_timebox_seconds
    _add(
        outcomes,
        "timebox",
        "pass" if ok else "fail",
        f"Timebox {context.timebox_seconds}s is within policy maximum {policy.max_timebox_seconds}s."
        if ok
        else f"Timebox {context.timebox_seconds}s exceeds policy maximum {policy.max_timebox_seconds}s.",
    )


def _evaluate_telemetry(policy: OpsecPolicy, context: OpsecContext, outcomes: list[dict[str, Any]]) -> None:
    del policy
    if context.operation in {"validation", "execution"} and context.mode == "confirmed":
        _add(
            outcomes,
            "expected_telemetry",
            "pass" if context.expected_telemetry else "warn",
            "Expected telemetry is recorded." if context.expected_telemetry else "Confirmed operation should record expected telemetry.",
        )
        _add(
            outcomes,
            "rollback",
            "pass" if context.rollback else "warn",
            "Rollback steps are recorded." if context.rollback else "Confirmed operation should record rollback steps.",
        )
    elif context.operation in {"source-check", "source-plan"} and (context.connect_check or context.source_trigger_required):
        _add(
            outcomes,
            "expected_telemetry",
            "pass" if context.expected_telemetry else "warn",
            "Expected telemetry is recorded for active or future-active source planning."
            if context.expected_telemetry
            else "Source planning should record expected telemetry.",
        )
        _add(
            outcomes,
            "rollback",
            "pass" if context.rollback else "warn",
            "Rollback steps are recorded for active or future-active source planning."
            if context.rollback
            else "Source planning should record rollback steps.",
        )
    else:
        _add(outcomes, "telemetry_boundary", "pass", "Telemetry and rollback review are not mandatory for this planning mode.")


def _extra_text(context: OpsecContext, key: str) -> str:
    return str(context.extra.get(key) or "").strip().lower()


def _requires_source_trigger(path: RelayPath, source_capability: str) -> bool:
    if path.source.lower() in ABSTRACT_SOURCES:
        return False
    return source_capability in SOURCE_TRIGGER_CAPABILITIES


def _min_noise(left: NoiseLevel, right: NoiseLevel) -> NoiseLevel:
    return left if NOISE_RANK[left] <= NOISE_RANK[right] else right


def _add(outcomes: list[dict[str, Any]], key: str, state: str, reason: str, *, evidence: dict[str, Any] | None = None) -> None:
    if state not in OPSEC_DECISIONS:
        raise ValueError(f"unsupported OPSEC outcome state: {state}")
    row = {"key": key, "state": state, "reason": reason}
    if evidence:
        row["evidence"] = evidence
    outcomes.append(row)


def _decision(outcomes: list[dict[str, Any]]) -> str:
    if any(row["state"] == "fail" for row in outcomes):
        return "fail"
    if any(row["state"] == "warn" for row in outcomes):
        return "warn"
    return "pass"


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if value in ("", None):
        return []
    return [str(value).strip()]
