from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import RelayPath, ScanResult
from .adapter_sdk import adapter_contract_for_module, default_adapter_registry
from .calculus import assess_path
from .evidence import evidence_value
from .execution import (
    EXECUTION_MODULES,
    HARD_STOP_DECISIONS,
    NON_READY_DECISIONS,
    ExecutionModuleSpec,
)


MODULE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")


def default_module_registry() -> dict[str, ExecutionModuleSpec]:
    return dict(EXECUTION_MODULES)


def load_module_registry(path: str | None = None, *, include_defaults: bool = True) -> dict[str, ExecutionModuleSpec]:
    registry = default_module_registry() if include_defaults else {}
    if not path:
        return registry
    root = Path(path)
    if not root.exists():
        raise ValueError(f"module manifest path does not exist: {path}")
    if root.is_dir():
        files = sorted(p for p in root.iterdir() if p.suffix.lower() == ".json")
    else:
        files = [root]
    for file_path in files:
        for spec in _load_module_file(file_path):
            registry[spec.key] = spec
    return registry


def module_inventory(registry: dict[str, ExecutionModuleSpec], module_key: str = "") -> dict:
    modules = _select_modules(registry, module_key)
    return {
        "name": "RelayX execution module inventory",
        "version": 1,
        "module_count": len(modules),
        "adapter_sdk": default_adapter_registry().describe(),
        "modules": [module.as_dict() for module in modules],
    }


def build_module_plan(
    result: ScanResult,
    path_id: str,
    registry: dict[str, ExecutionModuleSpec],
    *,
    module_key: str = "",
    mode: str = "confirmed",
    accept_non_ready: bool = False,
) -> dict:
    path = _path_by_id(result, path_id)
    assessment = assess_path(path)
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    modules = _select_modules(registry, module_key)
    evaluations = [
        _evaluate_module(
            path,
            module,
            target_family=assessment.target_family,
            source_capability=source_capability,
            decision=assessment.decision,
            mode=mode,
            accept_non_ready=accept_non_ready,
        )
        for module in modules
    ]
    return {
        "name": "RelayX execution module plan",
        "version": 1,
        "path_id": path.id,
        "target": path.target,
        "target_service": path.target_service,
        "source": path.source,
        "transport": path.transport,
        "target_family": assessment.target_family,
        "source_capability": source_capability,
        "decision": assessment.decision,
        "mode": mode,
        "accept_non_ready": accept_non_ready,
        "modules": evaluations,
    }


def render_module_inventory(inventory: dict) -> str:
    lines = [
        "RelayX Execution Modules",
        "",
        f"Modules: {inventory['module_count']}",
        f"Adapters: {len(inventory.get('adapter_sdk', {}).get('adapters', []))}",
    ]
    for module in inventory["modules"]:
        status = "supported" if module["supported"] else "unsupported"
        lines.extend(
            [
                "",
                f"- {module['key']} ({status})",
                f"  label: {module['label']}",
                f"  adapter: {module['adapter']}",
                f"  credential_policy: {module.get('credential_policy', 'none')}",
                f"  listener_policy: {module.get('listener_policy', 'none')}",
                f"  lab_only: {module.get('lab_only', False)}",
                f"  one_shot: {module.get('one_shot', True)}",
                f"  timeout_behavior: {module.get('timeout_behavior', 'fail_closed')}",
                f"  target_families: {', '.join(module['target_families'])}",
                f"  source_capabilities: {', '.join(module['source_capabilities'])}",
                f"  network_action: {module['network_action']}",
                f"  reason: {module['reason']}",
            ]
        )
    return "\n".join(lines)


def render_module_plan(plan: dict) -> str:
    lines = [
        "RelayX Module Plan",
        "",
        f"Path       : {plan['path_id']}",
        f"Target     : {plan['target']}",
        f"Service    : {plan['target_service']}",
        f"Decision   : {plan['decision']}",
        f"Family     : {plan['target_family']}",
        f"Capability : {plan['source_capability']}",
        f"Mode       : {plan['mode']}",
        "",
        "Modules:",
    ]
    for row in plan["modules"]:
        lines.append(
            f"  - {row['module']['key']}: state={row['state']} "
            f"applicable={row['applicable']} executable={row['executable']}"
        )
        for reason in row["reasons"]:
            lines.append(f"    why: {reason}")
        if row["warnings"]:
            for warning in row["warnings"]:
                lines.append(f"    warning: {warning}")
    return "\n".join(lines)


def module_inventory_to_json(inventory: dict) -> str:
    return json.dumps(inventory, indent=2, sort_keys=True)


def module_plan_to_json(plan: dict) -> str:
    return json.dumps(plan, indent=2, sort_keys=True)


def _load_module_file(path: Path) -> list[ExecutionModuleSpec]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"module manifest {path} is not valid JSON: {exc.msg}") from exc
    rows = data.get("modules", data) if isinstance(data, dict) else data
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise ValueError(f"module manifest {path} must be an object, a list, or an object with a 'modules' list")
    return [_module_from_plain(row, path) for row in rows]


def _module_from_plain(data: dict[str, Any], path: Path) -> ExecutionModuleSpec:
    if not isinstance(data, dict):
        raise ValueError(f"module manifest {path} contains a non-object entry")
    key = str(data.get("key", "")).strip().lower()
    if not MODULE_KEY_RE.fullmatch(key):
        raise ValueError(f"module manifest {path} has invalid key {key!r}")
    label = str(data.get("label") or key).strip()
    if not label:
        raise ValueError(f"module manifest {path} has an empty label for {key}")
    modes = tuple(_listish(data.get("modes", ["dry-run", "armed", "confirmed"])))
    invalid_modes = sorted(set(modes) - {"dry-run", "armed", "confirmed"})
    if invalid_modes:
        raise ValueError(f"module manifest {path} has invalid modes for {key}: {', '.join(invalid_modes)}")
    return ExecutionModuleSpec(
        key=key,
        label=label,
        version=str(data.get("version") or "external").strip() or "external",
        supported=_truthy(data.get("supported", False)),
        reason=str(data.get("reason") or "").strip() or "No module reason was supplied.",
        description=str(data.get("description") or "").strip(),
        target_families=tuple(_listish(data.get("target_families", ["*"]))),
        source_capabilities=tuple(_listish(data.get("source_capabilities", ["*"]))),
        modes=modes,
        network_action=str(data.get("network_action") or "none").strip().lower(),
        adapter=str(data.get("adapter") or "unsupported").strip().lower(),
        credential_policy=str(data.get("credential_policy") or "none").strip().lower(),
        listener_policy=str(data.get("listener_policy") or "none").strip().lower(),
        lifecycle=tuple(_listish(data.get("lifecycle", ["prepare", "execute", "cleanup"]))),
        requires=tuple(_listish(data.get("requires", []))),
        artifacts=tuple(_listish(data.get("artifacts", []))),
        forbidden_actions=tuple(_listish(data.get("forbidden_actions", []))),
        lab_only=_truthy(data.get("lab_only", False)),
        one_shot=_truthy(data.get("one_shot", True)),
        timeout_behavior=str(data.get("timeout_behavior") or "fail_closed").strip().lower(),
        timeout_seconds=max(0, int(data.get("timeout_seconds") or 0)),
        expected_telemetry=tuple(_listish_preserve_case(data.get("expected_telemetry", []))),
        evidence_capture=tuple(_listish(data.get("evidence_capture", []))),
    )


def _select_modules(registry: dict[str, ExecutionModuleSpec], module_key: str) -> list[ExecutionModuleSpec]:
    if module_key:
        key = module_key.strip().lower()
        if key not in registry:
            raise ValueError(f"No execution module matched {module_key!r}.")
        return [registry[key]]
    return [registry[key] for key in sorted(registry)]


def _evaluate_module(
    path: RelayPath,
    module: ExecutionModuleSpec,
    *,
    target_family: str,
    source_capability: str,
    decision: str,
    mode: str,
    accept_non_ready: bool,
) -> dict:
    target_match = _matches(module.target_families, target_family)
    source_match = _matches(module.source_capabilities, source_capability)
    mode_match = mode in module.modes
    reasons: list[str] = []
    warnings: list[str] = []
    if target_match:
        reasons.append(f"Target family {target_family} matches module manifest.")
    else:
        reasons.append(f"Target family {target_family} is not in module target_families.")
    if source_match:
        reasons.append(f"Source capability {source_capability} matches module manifest.")
    else:
        reasons.append(f"Source capability {source_capability} is not in module source_capabilities.")
    if mode_match:
        reasons.append(f"Mode {mode} is supported by the module manifest.")
    else:
        reasons.append(f"Mode {mode} is not supported by the module manifest.")

    applicable = target_match and source_match and mode_match
    executable = False
    if not applicable:
        state = "not_applicable"
    elif decision in HARD_STOP_DECISIONS:
        state = "blocked_by_calculus"
        reasons.append(f"Relay calculus decision {decision} is a hard stop.")
    elif decision in NON_READY_DECISIONS and not accept_non_ready:
        state = "needs_validation_or_calibration"
        reasons.append(f"Relay calculus decision {decision} requires validation or calibration before execution.")
    elif not module.supported:
        state = "unsupported"
        reasons.append(module.reason)
    else:
        state = "ready"
        executable = True
        reasons.append("Module is applicable, supported, and not blocked by RelayX calculus.")

    if module.network_action not in {"none", ""}:
        warnings.append(f"Module declares network_action={module.network_action}.")
    if _requires_source_trigger(path):
        warnings.append("Path depends on a modeled source-side trigger; RelayX module planning does not execute it.")

    return {
        "module": module.as_dict(),
        "adapter_sdk": adapter_contract_for_module(module.as_dict(), default_adapter_registry()),
        "state": state,
        "applicable": applicable,
        "executable": executable,
        "target_match": target_match,
        "source_match": source_match,
        "mode_match": mode_match,
        "reasons": reasons,
        "warnings": warnings,
        "expected_artifacts": list(module.artifacts),
        "expected_telemetry": list(module.expected_telemetry),
        "evidence_capture": list(module.evidence_capture),
        "required_inputs": list(module.requires),
        "forbidden_actions": list(module.forbidden_actions),
    }


def _matches(patterns: tuple[str, ...], value: str) -> bool:
    normalized = {item.strip().lower() for item in patterns if item.strip()}
    return "*" in normalized or value.lower() in normalized


def _requires_source_trigger(path: RelayPath) -> bool:
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    return source_capability in {
        "webclient",
        "spooler",
        "efsrpc",
        "dfsnm",
        "fsrvp",
        "mssql_outbound",
        "name_resolution",
    }


def _path_by_id(result: ScanResult, path_id: str) -> RelayPath:
    for path in result.paths:
        if path.id == path_id:
            return path
    raise ValueError(f"No path matched {path_id!r}.")


def _listish(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip().lower() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip().lower() for item in value if str(item).strip()]
    if value is None:
        return []
    return [part.strip().lower() for part in str(value).replace(";", ",").split(",") if part.strip()]


def _listish_preserve_case(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    return [part.strip() for part in str(value).replace(";", ",").split(",") if part.strip()]


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled", "supported"}
