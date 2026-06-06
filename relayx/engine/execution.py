from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ..models import Confidence, Evidence, EvidenceType, NoiseLevel, RelayPath, ScanResult, Status
from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterRegistry,
    adapter_contract_for_module,
    default_adapter_registry,
    execute_adapter,
    sdk_guardrails,
)
from .calculus import assess_path
from .evidence import evidence_value, upsert_evidence
from .opsec import build_dry_run_plan
from .opsec_policy import OpsecPolicy, evaluate_path_opsec, opsec_outcomes_as_guardrails
from .risk import estimate_noise
from .scope import ScopePolicy
from .source import NOISE_RANK


EXECUTION_MODES = {"dry-run", "armed", "confirmed"}
HARD_STOP_DECISIONS = {"blocked", "investigate_anomaly"}
NON_READY_DECISIONS = {"candidate_needs_calibration", "candidate_needs_validation"}
ABSTRACT_SOURCES = {
    "external_or_internal_ntlm_source",
    "webdav_or_http_ntlm_source",
    "mssql_or_coercible_ntlm_source",
}


@dataclass(frozen=True, slots=True)
class ExecutionModuleSpec:
    key: str
    label: str
    supported: bool
    reason: str
    version: str = "builtin"
    description: str = ""
    target_families: tuple[str, ...] = ("*",)
    source_capabilities: tuple[str, ...] = ("*",)
    modes: tuple[str, ...] = ("dry-run", "armed", "confirmed")
    network_action: str = "none"
    adapter: str = "unsupported"
    credential_policy: str = "none"
    listener_policy: str = "none"
    lifecycle: tuple[str, ...] = ("prepare", "execute", "cleanup")
    requires: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    forbidden_actions: tuple[str, ...] = ()
    lab_only: bool = False
    one_shot: bool = True
    timeout_behavior: str = "fail_closed"
    timeout_seconds: int = 0
    expected_telemetry: tuple[str, ...] = ()
    evidence_capture: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, str | bool | int | list[str]]:
        return {
            "key": self.key,
            "label": self.label,
            "version": self.version,
            "supported": self.supported,
            "reason": self.reason,
            "description": self.description,
            "target_families": list(self.target_families),
            "source_capabilities": list(self.source_capabilities),
            "modes": list(self.modes),
            "network_action": self.network_action,
            "adapter": self.adapter,
            "adapter_sdk_version": ADAPTER_SDK_VERSION,
            "credential_policy": self.credential_policy,
            "listener_policy": self.listener_policy,
            "lifecycle": list(self.lifecycle),
            "requires": list(self.requires),
            "artifacts": list(self.artifacts),
            "forbidden_actions": list(self.forbidden_actions),
            "lab_only": self.lab_only,
            "one_shot": self.one_shot,
            "timeout_behavior": self.timeout_behavior,
            "timeout_seconds": self.timeout_seconds,
            "expected_telemetry": list(self.expected_telemetry),
            "evidence_capture": list(self.evidence_capture),
        }


EXECUTION_MODULES: dict[str, ExecutionModuleSpec] = {
    "noop": ExecutionModuleSpec(
        key="noop",
        label="No-op execution adapter",
        supported=False,
        reason=(
            "No live relay module is selected. RelayX will produce an auditable "
            "execution record without starting listeners, coercion, or relay traffic."
        ),
        description="Built-in placeholder used when the operator has not selected an execution module.",
        adapter="unsupported",
        credential_policy="none",
        listener_policy="none",
        artifacts=("execution_record",),
        forbidden_actions=("listener_start", "credential_capture", "credential_forwarding", "source_trigger"),
    ),
    "relayx_audit_record": ExecutionModuleSpec(
        key="relayx_audit_record",
        label="RelayX offline audit record adapter",
        supported=True,
        reason=(
            "This adapter records a confirmed execution decision and evidence trail only. "
            "It performs no network action, starts no listener, and handles no credentials."
        ),
        description="Safe offline adapter for exercising the module contract and writing auditable evidence.",
        network_action="none",
        adapter="offline_audit_record",
        credential_policy="none",
        listener_policy="none",
        requires=("confirmed_operator_context", "audit_log"),
        artifacts=("execution_record", "jsonl_audit_entry", "optional_result_annotation"),
        forbidden_actions=("listener_start", "credential_capture", "credential_forwarding", "source_trigger"),
        expected_telemetry=(
            "RelayX JSONL audit entry for the controlled execution decision.",
            "No listener, credential handler, relay session, or source trigger telemetry is expected.",
        ),
        evidence_capture=("execution_record", "adapter_lifecycle", "jsonl_audit_entry"),
    ),
    "ntlmrelayx_compat": ExecutionModuleSpec(
        key="ntlmrelayx_compat",
        label="ntlmrelayx-inspired compatibility boundary",
        supported=False,
        reason=(
            "This records the future integration boundary for Impacket-style protocol "
            "clients. RelayX does not bundle a live relay adapter by default."
        ),
        description="Forward-looking manifest for an Impacket-style adapter boundary; intentionally unsupported.",
        network_action="future_relay_module",
        adapter="unsupported",
        credential_policy="none",
        listener_policy="none",
        requires=("lab_validated_adapter", "scoped_listener", "credential_handling_review"),
        artifacts=("execution_record", "module_plan"),
        forbidden_actions=("unscoped_listener", "credential_storage_without_policy", "source_trigger_without_plan"),
        lab_only=True,
        expected_telemetry=(
            "Lab-only fixture contract; no live telemetry is expected because the adapter is not registered.",
        ),
        evidence_capture=("module_plan", "execution_record_fixture"),
    ),
}


@dataclass(slots=True)
class ExecutionRequest:
    path_id: str
    mode: str = "dry-run"
    confirm: bool = False
    operator: str = ""
    reason: str = ""
    max_noise: NoiseLevel = NoiseLevel.HIGH
    timebox_seconds: int = 300
    scope: ScopePolicy | None = None
    audit_log: str = ""
    module: str = "noop"
    accept_non_ready: bool = False
    module_registry: dict[str, ExecutionModuleSpec] | None = field(default=None, repr=False)
    adapter_registry: AdapterRegistry | None = field(default=None, repr=False)
    opsec_policy: OpsecPolicy | None = field(default=None, repr=False)
    listener_host: str = ""
    callback_host: str = ""


def execute_path(result: ScanResult, request: ExecutionRequest) -> dict:
    path = _path_by_id(result, request.path_id)
    run = _base_run(path, request)
    run["opsec_policy"] = evaluate_path_opsec(
        path,
        policy=request.opsec_policy,
        operation="execution",
        mode=request.mode,
        max_noise=request.max_noise,
        scope=request.scope,
        timebox_seconds=request.timebox_seconds,
        confirm=request.confirm,
        operator=request.operator,
        reason=request.reason,
        audit_log=request.audit_log,
        network_action=_network_action_for_module(run["module"], request.mode),
        module=run["module"],
        expected_telemetry=run["expected_telemetry"],
        rollback=run["rollback"],
        extra={
            "accept_non_ready": request.accept_non_ready,
            "listener_host": request.listener_host,
            "callback_host": request.callback_host,
            "listener_required": run["module"].get("listener_policy") not in {"", "none"},
        },
    )
    guardrails = _guardrails(path, request, run["module"])
    guardrails.extend(sdk_guardrails(run["module"], request.adapter_registry or default_adapter_registry()))
    guardrails.extend(opsec_outcomes_as_guardrails(run["opsec_policy"]))
    run["guardrails"] = guardrails

    if any(item["state"] == "fail" for item in guardrails):
        run["result"] = {
            "state": "blocked",
            "reason": "One or more execution guardrails failed.",
        }
        _write_audit_if_requested(run, request.audit_log)
        return run

    if request.mode == "dry-run":
        run["result"] = {
            "state": "dry_run",
            "reason": "No execution action was performed.",
        }
    elif request.mode == "armed":
        run["result"] = {
            "state": "armed",
            "reason": "Execution plan passed guardrails; no execution action was performed.",
        }
    else:
        adapter_result = execute_adapter(
            run=run,
            path=path,
            operator=request.operator,
            reason=request.reason,
            audit_log=request.audit_log,
            timebox_seconds=request.timebox_seconds,
            registry=request.adapter_registry or default_adapter_registry(),
        )
        run["actions"].extend(adapter_result.actions)
        run["adapter_lifecycle"] = adapter_result.lifecycle
        run["artifacts"] = adapter_result.artifacts
        run["result"] = adapter_result.result

    _write_audit_if_requested(run, request.audit_log)
    return run


def apply_execution_to_result(result: ScanResult, run: dict) -> ScanResult:
    path = _path_by_id(result, str(run["path_id"]))
    upsert_evidence(
        path,
        Evidence(
            EvidenceType.OBSERVED,
            "relayx_execution_run",
            run["result"]["state"],
            Confidence.HIGH,
            detail="RelayX controlled execution record for this path.",
            raw={
                "run_id": run["run_id"],
                "started_at": run["started_at"],
                "mode": run["mode"],
                "operator": run.get("operator", ""),
                "reason": run.get("reason", ""),
                "module": run["module"],
                "decision": run["decision"],
                "result": run["result"],
                "guardrails": run["guardrails"],
                "opsec_policy": run.get("opsec_policy", {}),
                "execution_contract": run.get("execution_contract", {}),
                "adapter_sdk": run.get("adapter_sdk", {}),
                "adapter_lifecycle": run.get("adapter_lifecycle", []),
                "artifacts": run.get("artifacts", []),
                "actions": run["actions"],
            },
        ),
    )
    return result


def render_execution(run: dict) -> str:
    lines = [
        "RelayX Execution",
        "",
        f"Run ID     : {run['run_id']}",
        f"Mode       : {run['mode']}",
        f"Path       : {run['path_id']}",
        f"Decision   : {run['decision']}",
        f"Module     : {run['module']['key']} ({'supported' if run['module']['supported'] else 'unsupported'})",
        f"Adapter    : {run.get('adapter_sdk', {}).get('adapter', run['module'].get('adapter', '-'))}",
        f"Target     : {run['target']}",
        f"Service    : {run['target_service']}",
        f"Noise      : {run['noise']}",
        f"Result     : {run['result']['state']}",
        f"Reason     : {run['result']['reason']}",
        f"OPSEC      : {run.get('opsec_policy', {}).get('policy', {}).get('name', '-')} "
        f"decision={run.get('opsec_policy', {}).get('decision', '-')}",
        "",
        "Guardrails:",
    ]
    for guardrail in run["guardrails"]:
        lines.append(f"  - {guardrail['key']}: {guardrail['state']} - {guardrail['reason']}")
    if run.get("planned_steps"):
        lines.append("")
        lines.append("Planned Steps:")
        for step in run["planned_steps"]:
            lines.append(f"  - {step}")
    if run.get("actions"):
        lines.append("")
        lines.append("Actions:")
        for action in run["actions"]:
            lines.append(f"  - {action['type']}: {action['state']} - {action['reason']}")
    if run.get("adapter_lifecycle"):
        lines.append("")
        lines.append("Adapter Lifecycle:")
        for row in run["adapter_lifecycle"]:
            lines.append(f"  - {row['phase']}: {row['state']} - {row['reason']}")
    if run.get("scope_contract"):
        lines.append("")
        lines.append("Scope Contract:")
        for row in run["scope_contract"].get("guardrails", []):
            lines.append(f"  - {row['key']}: {row['state']} - {row['reason']}")
    if run.get("execution_contract"):
        contract = run["execution_contract"]
        lines.append("")
        lines.append("Execution Contract:")
        lines.append(f"  - one_shot: {contract.get('one_shot')}")
        lines.append(f"  - timeout_behavior: {contract.get('timeout_behavior')}")
        lines.append(f"  - effective_timeout_seconds: {contract.get('effective_timeout_seconds')}")
        if contract.get("lab_only"):
            lines.append("  - lab_only: true")
    if run.get("expected_telemetry"):
        lines.append("")
        lines.append("Expected Telemetry:")
        for item in run["expected_telemetry"]:
            lines.append(f"  - {item}")
    return "\n".join(lines)


def execution_to_json(run: dict) -> str:
    return json.dumps(run, indent=2, sort_keys=True)


def _path_by_id(result: ScanResult, path_id: str) -> RelayPath:
    for path in result.paths:
        if path.id == path_id:
            return path
    raise ValueError(f"No path matched {path_id!r}.")


def _base_run(path: RelayPath, request: ExecutionRequest) -> dict:
    if request.mode not in EXECUTION_MODES:
        raise ValueError(f"unsupported execution mode: {request.mode}")
    plan = build_dry_run_plan(path)
    assessment = assess_path(path)
    module = _module_spec(request.module, request.module_registry)
    module_dict = module.as_dict()
    adapter_registry = request.adapter_registry or default_adapter_registry()
    return {
        "run_id": f"RX-{uuid4().hex[:12]}",
        "started_at": datetime.now(UTC).isoformat(),
        "tool": "RelayX",
        "schema_version": 1,
        "mode": request.mode,
        "path_id": path.id,
        "operator": request.operator,
        "reason": request.reason,
        "decision": assessment.decision,
        "rule_id": assessment.rule_id,
        "source": path.source,
        "target": path.target,
        "transport": path.transport,
        "target_service": path.target_service,
        "source_capability": str(evidence_value(path, "source_capability", "generic")),
        "noise": estimate_noise(path).value,
        "timebox_seconds": request.timebox_seconds,
        "accept_non_ready": request.accept_non_ready,
        "module": module_dict,
        "scope_contract": _scope_contract(
            request.scope,
            source=path.source,
            target=path.target,
            listener_host=request.listener_host,
            callback_host=request.callback_host,
            listener_required=module.listener_policy not in {"", "none"},
        ),
        "execution_contract": _execution_contract(module, request.timebox_seconds),
        "adapter_sdk": adapter_contract_for_module(module_dict, adapter_registry),
        "preconditions": plan["preconditions"],
        "hardening_gates": plan["hardening_gates"],
        "operator_guardrails": plan["operator_guardrails"],
        "planned_steps": _planned_steps(module),
        "expected_telemetry": _unique_strings(plan["expected_telemetry"], module.expected_telemetry),
        "rollback": plan["rollback"],
        "boundaries": _boundaries(path),
        "execution": {
            "supported": module.supported,
            "module": module.key,
            "reason": module.reason,
        },
        "actions": [],
        "adapter_lifecycle": [],
        "artifacts": [],
    }


def _guardrails(path: RelayPath, request: ExecutionRequest, module: dict) -> list[dict]:
    decision = assess_path(path).decision
    guardrails = [
        _guardrail(
            "mode",
            request.mode in EXECUTION_MODES,
            f"Execution mode is {request.mode}.",
            f"Unsupported execution mode {request.mode}.",
        ),
        _guardrail(
            "single_path",
            bool(request.path_id.strip()),
            f"Single path selected: {request.path_id}.",
            "Execution requires exactly one path ID.",
        ),
        _guardrail(
            "path_status",
            path.status != Status.BLOCKED,
            "Path is not blocked.",
            "Path is blocked and cannot be executed.",
        ),
        _guardrail(
            "calculus_decision",
            decision not in HARD_STOP_DECISIONS,
            f"Relay calculus decision is {decision}.",
            f"Relay calculus decision {decision} is a hard stop.",
        ),
        _readiness_guardrail(decision, request),
        _guardrail(
            "timebox",
            request.timebox_seconds > 0,
            f"Timebox is {request.timebox_seconds} seconds.",
            "Timebox must be positive.",
        ),
        _guardrail(
            "confirmed_scope_required",
            request.mode != "confirmed" or (request.scope is not None and not request.scope.empty),
            "Confirmed execution has explicit scope."
            if request.mode == "confirmed"
            else "Explicit confirmed execution scope is not required for this mode.",
            "Confirmed execution requires explicit --scope.",
        ),
        _guardrail(
            "noise_budget",
            NOISE_RANK[estimate_noise(path)] <= NOISE_RANK[request.max_noise],
            f"Path noise {estimate_noise(path).value} is within max-noise {request.max_noise.value}.",
            f"Path noise {estimate_noise(path).value} exceeds max-noise {request.max_noise.value}.",
        ),
        {
            "key": "source_trigger_boundary",
            "state": "warn" if _requires_source_trigger(path) else "pass",
            "reason": (
                "Path depends on a modeled source-side trigger; RelayX controlled execution does not execute source triggers."
                if _requires_source_trigger(path)
                else "No source-side trigger is executed by this run."
            ),
        },
        _guardrail(
            "module_registered",
            module["key"] in _registry_for_request(request),
            f"Execution module {module['key']} is registered.",
            f"Execution module {module['key']} is not registered.",
        ),
        _guardrail(
            "module_mode",
            request.mode in module["modes"],
            f"Execution module {module['key']} supports mode {request.mode}.",
            f"Execution module {module['key']} does not support mode {request.mode}.",
        ),
        _module_support_guardrail(module, request.mode),
        _lab_only_guardrail(module, request.mode),
        _execution_contract_guardrail(module, request.timebox_seconds),
        _source_trigger_target_relay_guardrail(path, request, module),
    ]
    if request.scope:
        guardrails.append(
            _guardrail(
                "scope_target",
                request.scope.contains(path.target),
                "Target is inside supplied scope.",
                "Target is outside supplied scope.",
            )
        )
        if path.source and path.source.lower() not in ABSTRACT_SOURCES:
            guardrails.append(
                _guardrail(
                    "scope_source",
                    request.scope.contains(path.source),
                    "Source is inside supplied scope.",
                    "Source is outside supplied scope.",
                )
            )
    if request.mode == "confirmed":
        guardrails.extend(
            [
                _guardrail(
                    "confirm_flag",
                    request.confirm,
                    "Explicit confirmation flag supplied.",
                    "Confirmed execution requires --confirm.",
                ),
                _guardrail(
                    "operator",
                    bool(request.operator.strip()),
                    "Operator identity supplied.",
                    "Confirmed execution requires --operator.",
                ),
                _guardrail(
                    "reason",
                    bool(request.reason.strip()),
                    "Execution reason supplied.",
                    "Confirmed execution requires --reason.",
                ),
                _guardrail(
                    "audit_log",
                    bool(request.audit_log.strip()),
                    "Audit log path supplied.",
                    "Confirmed execution requires --audit-log.",
                ),
            ]
        )
    scope_contract = _scope_contract(
        request.scope,
        source=path.source,
        target=path.target,
        listener_host=request.listener_host,
        callback_host=request.callback_host,
        listener_required=module.get("listener_policy") not in {"", "none"},
    )
    guardrails.extend(scope_contract["guardrails"])
    return guardrails


def _readiness_guardrail(decision: str, request: ExecutionRequest) -> dict:
    if decision in HARD_STOP_DECISIONS:
        return {
            "key": "calculus_readiness",
            "state": "fail",
            "reason": f"Relay calculus decision {decision} cannot proceed.",
        }
    if decision in NON_READY_DECISIONS and request.mode == "confirmed" and not request.accept_non_ready:
        return {
            "key": "calculus_readiness",
            "state": "fail",
            "reason": (
                f"Relay calculus decision {decision} requires --accept-non-ready "
                "before confirmed execution planning."
            ),
        }
    if decision in NON_READY_DECISIONS:
        return {
            "key": "calculus_readiness",
            "state": "warn",
            "reason": f"Relay calculus decision is {decision}; execution remains planning-only unless explicitly accepted.",
        }
    return {
        "key": "calculus_readiness",
        "state": "pass",
        "reason": f"Relay calculus decision is {decision}.",
    }


def _execution_contract(module: ExecutionModuleSpec, request_timebox_seconds: int) -> dict:
    module_timeout = max(0, int(module.timeout_seconds or 0))
    effective_timeout = module_timeout or max(0, int(request_timebox_seconds))
    return {
        "lab_only": module.lab_only,
        "one_shot": module.one_shot,
        "timeout_behavior": module.timeout_behavior,
        "module_timeout_seconds": module_timeout,
        "request_timebox_seconds": request_timebox_seconds,
        "effective_timeout_seconds": effective_timeout,
        "expected_telemetry": list(module.expected_telemetry),
        "evidence_capture": list(module.evidence_capture),
    }


def _module_support_guardrail(module: dict, mode: str) -> dict:
    if module["supported"]:
        return {
            "key": "module_support",
            "state": "pass",
            "reason": module["reason"],
        }
    network_action = str(module.get("network_action") or "none")
    adapter = str(module.get("adapter") or "unsupported")
    unsafe_confirmed_boundary = mode == "confirmed" and (adapter != "unsupported" or network_action not in {"", "none"})
    return {
        "key": "module_support",
        "state": "fail" if unsafe_confirmed_boundary else "warn",
        "reason": (
            "Unsupported modules with a non-placeholder adapter or network action cannot run in confirmed mode."
            if unsafe_confirmed_boundary
            else module["reason"]
        ),
    }


def _lab_only_guardrail(module: dict, mode: str) -> dict:
    if not module.get("lab_only"):
        return {
            "key": "lab_only_live_module_boundary",
            "state": "pass",
            "reason": "Module is not marked lab-only.",
        }
    return {
        "key": "lab_only_live_module_boundary",
        "state": "fail" if mode == "confirmed" else "warn",
        "reason": (
            "Lab-only modules cannot run in confirmed mode until they pass protocol design, "
            "credential handling, OPSEC, and authorized lab regression reviews."
            if mode == "confirmed"
            else "Module is lab-only; RelayX treats it as a planning and fixture boundary only."
        ),
    }


def _execution_contract_guardrail(module: dict, request_timebox_seconds: int) -> dict:
    one_shot = bool(module.get("one_shot", True))
    timeout_behavior = str(module.get("timeout_behavior") or "fail_closed")
    timeout_seconds = int(module.get("timeout_seconds") or 0)
    if timeout_seconds and timeout_seconds > request_timebox_seconds:
        return {
            "key": "execution_timeout",
            "state": "fail",
            "reason": (
                f"Module timeout {timeout_seconds}s exceeds execution timebox "
                f"{request_timebox_seconds}s."
            ),
        }
    if not one_shot and module.get("supported"):
        return {
            "key": "execution_one_shot",
            "state": "fail",
            "reason": "Supported execution modules must declare one-shot execution behavior.",
        }
    if timeout_behavior not in {"fail_closed", "record_only", "not_applicable"}:
        return {
            "key": "execution_timeout_behavior",
            "state": "fail",
            "reason": f"Unsupported timeout behavior {timeout_behavior}.",
        }
    return {
        "key": "execution_contract",
        "state": "pass",
        "reason": (
            "Execution contract declares one-shot behavior and fail-closed timeout handling."
            if one_shot and timeout_behavior == "fail_closed"
            else f"Execution contract declares one_shot={one_shot} timeout_behavior={timeout_behavior}."
        ),
    }


def _source_trigger_target_relay_guardrail(path: RelayPath, request: ExecutionRequest, module: dict) -> dict:
    network_action = str(module.get("network_action") or "none")
    requires_source_trigger = _requires_source_trigger(path)
    if not requires_source_trigger:
        return {
            "key": "source_trigger_target_relay_separation",
            "state": "pass",
            "reason": "Path does not require a source-side trigger.",
        }
    if network_action in {"", "none"}:
        return {
            "key": "source_trigger_target_relay_separation",
            "state": "pass" if request.mode != "confirmed" else "warn",
            "reason": "Source-trigger path remains separated because selected module performs no target relay network action.",
        }
    return {
        "key": "source_trigger_target_relay_separation",
        "state": "fail" if request.mode == "confirmed" else "warn",
        "reason": (
            "Source-side trigger planning and target relay execution must be individually scoped and audited "
            "before a network execution module may run."
        ),
    }


def _network_action_for_module(module: dict, mode: str) -> str:
    if mode == "confirmed" and module.get("adapter") == "offline_audit_record":
        return "offline_audit_record"
    return str(module.get("network_action") or "none")


def _module_spec(name: str, registry: dict[str, ExecutionModuleSpec] | None = None) -> ExecutionModuleSpec:
    module_registry = registry if registry is not None else EXECUTION_MODULES
    key = (name or "noop").strip().lower()
    return module_registry.get(
        key,
        ExecutionModuleSpec(
            key=key,
            label="Unknown execution adapter",
            supported=False,
            reason="Unknown execution module. Register and test a module before using it.",
        ),
    )


def _registry_for_request(request: ExecutionRequest) -> dict[str, ExecutionModuleSpec]:
    return request.module_registry if request.module_registry is not None else EXECUTION_MODULES


def _guardrail(key: str, ok: bool, pass_reason: str, fail_reason: str) -> dict:
    return {
        "key": key,
        "state": "pass" if ok else "fail",
        "reason": pass_reason if ok else fail_reason,
    }


def _requires_source_trigger(path: RelayPath) -> bool:
    source = path.source.lower()
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    if source in ABSTRACT_SOURCES:
        return False
    return source_capability in {
        "webclient",
        "spooler",
        "efsrpc",
        "dfsnm",
        "fsrvp",
        "mssql_outbound",
        "name_resolution",
    }


def _planned_steps(module: ExecutionModuleSpec) -> list[str]:
    return [
        "Load one RelayX path by ID and bind it to the operator audit context.",
        "Evaluate path status, relay calculus decision, scope, OPSEC noise, and timebox guardrails.",
        f"Resolve execution module {module.key} and record whether live execution is supported.",
        "Write an audit entry and optional annotated RelayX result before any future network execution.",
        "Stop before source triggers or credential relay unless a future supported module passes the same guardrails.",
    ]


def _boundaries(path: RelayPath) -> list[str]:
    boundaries = [
        "no_unscoped_path_execution",
        "no_implicit_operator_confirmation",
        "no_live_relay_module_by_default",
        "no_credential_capture_or_forwarding_in_execution_core",
    ]
    if _requires_source_trigger(path):
        boundaries.append("no_source_side_trigger_execution")
    return boundaries


def _scope_contract(
    scope: ScopePolicy | None,
    *,
    source: str,
    target: str,
    listener_host: str,
    callback_host: str,
    listener_required: bool,
) -> dict:
    del source, target
    scope_present = scope is not None and not scope.empty
    guardrails = []
    if listener_host:
        guardrails.append(
            _guardrail(
                "scope_listener",
                bool(scope and scope.contains(listener_host)),
                "Listener host is inside supplied scope.",
                "Listener host is outside supplied scope.",
            )
        )
    elif listener_required:
        guardrails.append(
            {
                "key": "scope_listener",
                "state": "warn",
                "reason": "Execution module has a listener policy but no listener host was supplied.",
            }
        )
    if callback_host:
        guardrails.append(
            _guardrail(
                "scope_callback",
                bool(scope and scope.contains(callback_host)),
                "Callback host is inside supplied scope.",
                "Callback host is outside supplied scope.",
            )
        )
    if not scope_present and (listener_host or callback_host):
        guardrails.append(
            {
                "key": "scope_explicit_listener_callback",
                "state": "fail",
                "reason": "Listener or callback planning was supplied without explicit scope.",
            }
        )
    return {
        "scope_present": scope_present,
        "listener_host": listener_host,
        "callback_host": callback_host,
        "listener_required": listener_required,
        "guardrails": guardrails,
    }


def _unique_strings(*groups: tuple[str, ...] | list[str]) -> list[str]:
    seen: set[str] = set()
    rows: list[str] = []
    for group in groups:
        for item in group:
            text = str(item).strip()
            if not text or text in seen:
                continue
            rows.append(text)
            seen.add(text)
    return rows


def _write_audit_if_requested(run: dict, audit_log: str) -> None:
    if not audit_log:
        return
    path = Path(audit_log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(run, sort_keys=True) + "\n")
