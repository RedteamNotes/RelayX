from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ..models import NoiseLevel, RelayPath, ScanResult, Status
from ..oracles import http, ldap, mssql, smb
from .calculus import assess_path
from .opsec import build_dry_run_plan
from .operation_control import (
    OperationControl,
    OperationControlError,
    ensure_operation_window,
    initial_delay_seconds,
    operation_control_guardrails,
    unique_strings,
)
from .opsec_policy import OpsecPolicy, evaluate_path_opsec, opsec_outcomes_as_guardrails
from .risk import estimate_noise
from .scope import ScopePolicy
from .source import NOISE_RANK


VALIDATION_MODES = {"dry-run", "armed", "confirmed"}


@dataclass(slots=True)
class ValidationRequest:
    path_id: str
    mode: str = "dry-run"
    confirm: bool = False
    operator: str = ""
    reason: str = ""
    max_noise: NoiseLevel = NoiseLevel.HIGH
    timebox_seconds: int = 300
    scope: ScopePolicy | None = None
    audit_log: str = ""
    reprobe: bool = False
    auth_validation: bool = False
    timeout: float = 3.0
    opsec_policy: OpsecPolicy | None = None
    operation_control: OperationControl = field(default_factory=OperationControl)


def validate_path(result: ScanResult, request: ValidationRequest) -> dict:
    path = _path_by_id(result, request.path_id)
    run = _base_run(path, request)
    run["opsec_policy"] = evaluate_path_opsec(
        path,
        policy=request.opsec_policy,
        operation="validation",
        mode=request.mode,
        max_noise=request.max_noise,
        scope=request.scope,
        timebox_seconds=request.timebox_seconds,
        confirm=request.confirm,
        operator=request.operator,
        reason=request.reason,
        audit_log=request.audit_log,
        auth_validation=request.auth_validation,
        reprobe=request.reprobe,
        network_action="target_reprobe" if request.reprobe else "none",
        expected_telemetry=run["expected_telemetry"],
        rollback=run["rollback"],
    )
    guardrails = _guardrails(path, request)
    guardrails.extend(operation_control_guardrails(run["operation_control"]))
    guardrails.extend(opsec_outcomes_as_guardrails(run["opsec_policy"]))
    run["guardrails"] = guardrails
    if any(item["state"] == "fail" for item in guardrails):
        run["result"] = {
            "state": "blocked",
            "reason": "One or more validation guardrails failed.",
        }
        _write_audit_if_requested(run, request.audit_log)
        return run

    if request.mode == "dry-run":
        run["result"] = {
            "state": "dry_run",
            "reason": "No active validation was performed.",
        }
    elif request.mode == "armed":
        run["result"] = {
            "state": "armed",
            "reason": "Validation plan passed guardrails but no network action was performed.",
        }
    else:
        delay = initial_delay_seconds(request.operation_control)
        try:
            if request.reprobe:
                ensure_operation_window(request.operation_control)
                if delay > 0:
                    time.sleep(delay)
                    ensure_operation_window(request.operation_control)
                    run["actions"].append(
                        {
                            "type": "operation_delay",
                            "state": "completed",
                            "reason": f"Applied configured pre-action delay of {delay:.3f} seconds.",
                        }
                    )
        except OperationControlError as exc:
            run["guardrails"].append(
                {
                    "key": "operation_window_runtime",
                    "state": "fail",
                    "reason": str(exc),
                }
            )
            run["result"] = {
                "state": "blocked",
                "reason": "Operation window closed before confirmed validation action.",
            }
            _write_audit_if_requested(run, request.audit_log)
            return run
        result_state, actions = _confirmed_result(path, request)
        run["actions"].extend(actions)
        run["result"] = result_state

    _write_audit_if_requested(run, request.audit_log)
    return run


def render_validation(run: dict) -> str:
    lines = [
        "RelayX Validation",
        "",
        f"Run ID     : {run['run_id']}",
        f"Mode       : {run['mode']}",
        f"Path       : {run['path_id']}",
        f"Decision   : {run['decision']}",
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
    if run.get("actions"):
        lines.append("")
        lines.append("Actions:")
        for action in run["actions"]:
            lines.append(f"  - {action['type']}: {action['state']} - {action['reason']}")
    if run.get("expected_telemetry"):
        lines.append("")
        lines.append("Expected Telemetry:")
        for item in run["expected_telemetry"]:
            lines.append(f"  - {item}")
    return "\n".join(lines)


def validation_to_json(run: dict) -> str:
    return json.dumps(run, indent=2, sort_keys=True)


def _path_by_id(result: ScanResult, path_id: str) -> RelayPath:
    for path in result.paths:
        if path.id == path_id:
            return path
    raise ValueError(f"No path matched {path_id!r}.")


def _base_run(path: RelayPath, request: ValidationRequest) -> dict:
    if request.mode not in VALIDATION_MODES:
        raise ValueError(f"unsupported validation mode: {request.mode}")
    plan = build_dry_run_plan(path)
    assessment = assess_path(path)
    active_operation = request.mode == "confirmed" and request.reprobe
    control_report = request.operation_control.report(
        operation="validation",
        active_operation=active_operation,
        action_count=1 if active_operation else 0,
        network_action="target_reprobe" if request.reprobe else "none",
    )
    return {
        "run_id": f"VX-{uuid4().hex[:12]}",
        "started_at": datetime.now(UTC).isoformat(),
        "tool": "RelayX",
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
        "noise": estimate_noise(path).value,
        "timebox_seconds": request.timebox_seconds,
        "reprobe_requested": request.reprobe,
        "auth_validation_requested": request.auth_validation,
        "operation_control": control_report,
        "expected_telemetry": unique_strings(plan["expected_telemetry"], control_report["expected_telemetry"]),
        "rollback": unique_strings(plan["rollback"], control_report["rollback"]),
        "actions": [],
    }


def _guardrails(path: RelayPath, request: ValidationRequest) -> list[dict]:
    guardrails = [
        _guardrail(
            "mode",
            request.mode in VALIDATION_MODES,
            f"Validation mode is {request.mode}.",
            f"Unsupported validation mode {request.mode}.",
        ),
        _guardrail(
            "path_status",
            path.status != Status.BLOCKED,
            "Path is not blocked.",
            "Path is blocked and cannot be actively validated.",
        ),
        _guardrail(
            "timebox",
            request.timebox_seconds > 0,
            f"Timebox is {request.timebox_seconds} seconds.",
            "Timebox must be positive.",
        ),
        _guardrail(
            "noise_budget",
            NOISE_RANK[estimate_noise(path)] <= NOISE_RANK[request.max_noise],
            f"Path noise {estimate_noise(path).value} is within max-noise {request.max_noise.value}.",
            f"Path noise {estimate_noise(path).value} exceeds max-noise {request.max_noise.value}.",
        ),
        {
            "key": "source_trigger_boundary",
            "state": "pass",
            "reason": (
                "Path depends on a modeled source-side trigger; RelayX validation will not execute it."
                if _requires_source_trigger(path)
                else "No source-side trigger is required for this validation harness step."
            ),
        },
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
        if path.source and not path.source.startswith("external_or_internal"):
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
                    "Confirmed validation requires --confirm.",
                ),
                _guardrail(
                    "operator",
                    bool(request.operator.strip()),
                    "Operator identity supplied.",
                    "Confirmed validation requires --operator.",
                ),
                _guardrail(
                    "reason",
                    bool(request.reason.strip()),
                    "Validation reason supplied.",
                    "Confirmed validation requires --reason.",
                ),
                _guardrail(
                    "audit_log",
                    bool(request.audit_log.strip()),
                    "Audit log path supplied.",
                    "Confirmed validation requires --audit-log.",
                ),
            ]
        )
    if request.auth_validation:
        guardrails.append(
            _guardrail(
                "auth_validation_requires_confirmed_reprobe",
                request.mode == "confirmed" and request.confirm and request.reprobe,
                "Synthetic authenticate validation is gated behind confirmed target reprobe.",
                "Synthetic authenticate validation requires confirmed mode, --confirm, and --reprobe.",
            )
        )
    return guardrails


def _guardrail(key: str, ok: bool, pass_reason: str, fail_reason: str) -> dict:
    return {
        "key": key,
        "state": "pass" if ok else "fail",
        "reason": pass_reason if ok else fail_reason,
    }


def _requires_source_trigger(path: RelayPath) -> bool:
    source = path.source.lower()
    capability_values = [
        evidence.value
        for evidence in path.evidence
        if evidence.key == "source_capability"
    ]
    source_capability = str(capability_values[0]) if capability_values else "generic"
    if source in {"external_or_internal_ntlm_source", "webdav_or_http_ntlm_source", "mssql_or_coercible_ntlm_source"}:
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


def _confirmed_result(path: RelayPath, request: ValidationRequest) -> tuple[dict, list[dict]]:
    if not request.reprobe:
        return (
            {
                "state": "confirmed_noop",
                "reason": "Confirmed validation passed guardrails; no reprobe was requested.",
            },
            [],
        )
    action = _target_reprobe(path, request)
    return (
        {
            "state": action["state"],
            "reason": action["reason"],
        },
        [action],
    )


def _target_reprobe(path: RelayPath, request: ValidationRequest) -> dict:
    protocol = _target_protocol(path)
    try:
        if protocol == "smb":
            finding = smb.assess(path.target, timeout=request.timeout)
        elif protocol in {"http", "https"}:
            finding = http.assess(
                path.target,
                port=_target_port(path),
                scheme=protocol,
                timeout=request.timeout,
                paths=[_target_http_path(path)],
                challenge_flow=True,
                auth_validation=request.auth_validation,
            )[0]
        elif protocol in {"ldap", "ldaps"}:
            finding = ldap.assess(
                path.target,
                port=_target_port(path),
                timeout=request.timeout,
                challenge_flow=True,
                auth_validation=request.auth_validation,
            )
        elif protocol == "mssql":
            finding = mssql.assess(
                path.target,
                port=_target_port(path),
                timeout=request.timeout,
                prefer_tls=True,
                auth_validation=request.auth_validation,
            )
        else:
            return {
                "type": "target_reprobe",
                "state": "unsupported",
                "reason": f"Unsupported target protocol {protocol}.",
            }
    except OSError as exc:
        return {
            "type": "target_reprobe",
            "state": "error",
            "reason": str(exc),
        }
    return {
        "type": "target_reprobe",
        "state": "observed",
        "reason": f"Target-side {protocol} reprobe completed.",
        "finding": {
            "host": finding.host,
            "port": finding.port,
            "protocol": finding.protocol,
            "name": finding.name,
            "status": finding.status.value,
            "confidence": finding.confidence.value,
            "summary": finding.summary,
        },
    }


def _target_protocol(path: RelayPath) -> str:
    service = path.target_service.lower()
    if service.startswith("https/"):
        return "https"
    if service.startswith("http/"):
        return "http"
    if service.startswith("ldaps/"):
        return "ldaps"
    if service.startswith("ldap/"):
        return "ldap"
    if service.startswith("mssql/"):
        return "mssql"
    if service.startswith("smb/"):
        return "smb"
    if "mssql" in path.transport.lower():
        return "mssql"
    return path.transport.split("->")[-1].strip().lower()


def _target_port(path: RelayPath) -> int:
    service = path.target_service.split()[0]
    if "/" in service:
        _, port = service.split("/", 1)
        try:
            return int(port)
        except ValueError:
            pass
    return {
        "http": 80,
        "https": 443,
        "ldap": 389,
        "ldaps": 636,
        "mssql": 1433,
        "smb": 445,
    }[_target_protocol(path)]


def _target_http_path(path: RelayPath) -> str:
    service = path.target_service.lower()
    if "/certsrv" in service:
        return "/certsrv/"
    if "/wsman" in service:
        return "/wsman"
    return "/"


def _write_audit_if_requested(run: dict, audit_log: str) -> None:
    if not audit_log:
        return
    path = Path(audit_log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(run, sort_keys=True) + "\n")
