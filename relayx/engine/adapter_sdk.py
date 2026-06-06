from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from ..models import RelayPath


ADAPTER_SDK_VERSION = 1

SAFE_CREDENTIAL_POLICIES = {
    "none",
    "no_credentials",
    "synthetic_only",
}
SAFE_LISTENER_POLICIES = {
    "none",
    "no_listener",
}


@dataclass(frozen=True, slots=True)
class AdapterContext:
    run_id: str
    mode: str
    module: dict[str, Any]
    path: RelayPath
    operator: str = ""
    reason: str = ""
    audit_log: str = ""
    timebox_seconds: int = 300

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "module": self.module.get("key", ""),
            "path_id": self.path.id,
            "source": self.path.source,
            "target": self.path.target,
            "target_service": self.path.target_service,
            "operator_supplied": bool(self.operator),
            "reason_supplied": bool(self.reason),
            "audit_log_supplied": bool(self.audit_log),
            "timebox_seconds": self.timebox_seconds,
        }


@dataclass(slots=True)
class AdapterOutcome:
    phase: str
    state: str
    reason: str
    network_action: bool = False
    artifacts: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_action(self, adapter_key: str) -> dict[str, Any]:
        action = {
            "type": f"adapter_{self.phase}",
            "state": self.state,
            "reason": self.reason,
            "adapter": adapter_key,
            "network_action": self.network_action,
        }
        if self.artifacts:
            action["artifacts"] = list(self.artifacts)
        if self.details:
            action["details"] = dict(self.details)
        return action


@dataclass(slots=True)
class AdapterRunResult:
    result: dict[str, str]
    actions: list[dict[str, Any]]
    lifecycle: list[dict[str, Any]]
    artifacts: list[str] = field(default_factory=list)


class ExecutionAdapter(Protocol):
    key: str
    label: str
    network_action: str
    credential_policy: str
    listener_policy: str
    lifecycle: tuple[str, ...]

    def describe(self) -> dict[str, Any]:
        ...

    def run(self, context: AdapterContext) -> AdapterRunResult:
        ...


class BaseExecutionAdapter:
    key = "unsupported"
    label = "Unsupported adapter"
    network_action = "none"
    credential_policy = "none"
    listener_policy = "none"
    lifecycle = ("prepare", "execute", "cleanup")
    one_shot = True
    timeout_behavior = "fail_closed"
    expected_telemetry = ("RelayX adapter lifecycle record.",)
    evidence_capture = ("adapter_lifecycle", "execution_record")

    def describe(self) -> dict[str, Any]:
        return {
            "sdk_version": ADAPTER_SDK_VERSION,
            "key": self.key,
            "label": self.label,
            "network_action": self.network_action,
            "credential_policy": self.credential_policy,
            "listener_policy": self.listener_policy,
            "lifecycle": list(self.lifecycle),
            "one_shot": self.one_shot,
            "timeout_behavior": self.timeout_behavior,
            "expected_telemetry": list(self.expected_telemetry),
            "evidence_capture": list(self.evidence_capture),
        }

    def run(self, context: AdapterContext) -> AdapterRunResult:
        outcomes = [
            self.prepare(context),
            self.execute(context),
            self.cleanup(context),
        ]
        return AdapterRunResult(
            result=self.result_state(outcomes),
            actions=[outcome.as_action(self.key) for outcome in outcomes],
            lifecycle=[_lifecycle_row(outcome) for outcome in outcomes],
            artifacts=_artifacts(outcomes),
        )

    def prepare(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="prepare",
            state="prepared",
            reason="Adapter context was prepared.",
        )

    def execute(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="execute",
            state="not_available",
            reason="Adapter does not implement execution.",
        )

    def cleanup(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="cleanup",
            state="completed",
            reason="Adapter cleanup completed.",
        )

    def result_state(self, outcomes: list[AdapterOutcome]) -> dict[str, str]:
        if any(outcome.state in {"failed", "blocked"} for outcome in outcomes):
            return {
                "state": "adapter_failed",
                "reason": "Adapter lifecycle failed.",
            }
        return {
            "state": "not_implemented",
            "reason": "Adapter lifecycle completed without an implemented execution phase.",
        }


class UnsupportedAdapter(BaseExecutionAdapter):
    key = "unsupported"
    label = "Unsupported adapter boundary"
    network_action = "none"
    credential_policy = "none"
    listener_policy = "none"

    def execute(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="execute",
            state="not_available",
            reason=context.module.get("reason") or "The selected module is not supported by RelayX.",
            artifacts=list(context.module.get("artifacts") or []),
        )

    def result_state(self, outcomes: list[AdapterOutcome]) -> dict[str, str]:
        return {
            "state": "no_module_available",
            "reason": "Confirmed execution passed guardrails, but no supported live relay module is available.",
        }


class OfflineAuditRecordAdapter(BaseExecutionAdapter):
    key = "offline_audit_record"
    label = "Offline audit record adapter"
    network_action = "none"
    credential_policy = "none"
    listener_policy = "none"
    expected_telemetry = (
        "RelayX JSONL audit entry and execution record.",
        "No network telemetry is expected because the adapter performs no network action.",
    )
    evidence_capture = ("execution_record", "adapter_lifecycle", "jsonl_audit_entry")

    def prepare(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="prepare",
            state="prepared",
            reason="Offline adapter bound the path, operator context, and audit destination.",
            details={
                "operator_supplied": bool(context.operator),
                "audit_log_supplied": bool(context.audit_log),
                "timebox_seconds": context.timebox_seconds,
            },
        )

    def execute(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="execute",
            state="executed",
            reason=context.module.get("reason") or "Offline audit adapter recorded the execution decision.",
            network_action=False,
            artifacts=list(context.module.get("artifacts") or ["execution_record"]),
            details={
                "recorded_at": datetime.now(UTC).isoformat(),
                "credential_handling": "none",
                "listener_lifecycle": "none",
                "one_shot": self.one_shot,
                "timeout_behavior": self.timeout_behavior,
                "evidence_capture": list(self.evidence_capture),
            },
        )

    def cleanup(self, context: AdapterContext) -> AdapterOutcome:
        return AdapterOutcome(
            phase="cleanup",
            state="completed",
            reason="No listener, credential state, or network resource required cleanup.",
        )

    def result_state(self, outcomes: list[AdapterOutcome]) -> dict[str, str]:
        return {
            "state": "executed_offline",
            "reason": "Confirmed execution was recorded by the RelayX offline audit adapter.",
        }


class AdapterRegistry:
    def __init__(self, adapters: list[ExecutionAdapter] | None = None):
        self._adapters: dict[str, ExecutionAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: ExecutionAdapter) -> None:
        self._adapters[adapter.key] = adapter

    def get(self, key: str) -> ExecutionAdapter | None:
        return self._adapters.get(key)

    def describe(self) -> dict[str, Any]:
        return {
            "name": "RelayX execution adapter registry",
            "version": ADAPTER_SDK_VERSION,
            "adapters": [adapter.describe() for adapter in sorted(self._adapters.values(), key=lambda item: item.key)],
        }

    def keys(self) -> set[str]:
        return set(self._adapters)


def default_adapter_registry() -> AdapterRegistry:
    return AdapterRegistry([UnsupportedAdapter(), OfflineAuditRecordAdapter()])


def build_adapter_context(
    *,
    run: dict[str, Any],
    path: RelayPath,
    operator: str,
    reason: str,
    audit_log: str,
    timebox_seconds: int,
) -> AdapterContext:
    return AdapterContext(
        run_id=str(run["run_id"]),
        mode=str(run["mode"]),
        module=dict(run["module"]),
        path=path,
        operator=operator,
        reason=reason,
        audit_log=audit_log,
        timebox_seconds=timebox_seconds,
    )


def adapter_contract_for_module(module: dict[str, Any], registry: AdapterRegistry | None = None) -> dict[str, Any]:
    adapter_key = str(module.get("adapter") or "unsupported")
    adapter = (registry or default_adapter_registry()).get(adapter_key)
    manifest_policy = {
        "credential_policy": str(module.get("credential_policy") or (adapter.credential_policy if adapter else "unknown")),
        "listener_policy": str(module.get("listener_policy") or (adapter.listener_policy if adapter else "unknown")),
        "network_action": str(module.get("network_action") or "none"),
        "lifecycle": list(module.get("lifecycle") or (adapter.lifecycle if adapter else ())),
        "one_shot": bool(module.get("one_shot", adapter.one_shot if adapter else True)),
        "timeout_behavior": str(module.get("timeout_behavior") or (adapter.timeout_behavior if adapter else "fail_closed")),
        "timeout_seconds": int(module.get("timeout_seconds") or 0),
        "expected_telemetry": list(module.get("expected_telemetry") or (adapter.expected_telemetry if adapter else ())),
        "evidence_capture": list(module.get("evidence_capture") or (adapter.evidence_capture if adapter else ())),
        "lab_only": bool(module.get("lab_only", False)),
    }
    return {
        "sdk_version": ADAPTER_SDK_VERSION,
        "adapter": adapter_key,
        "registered": adapter is not None,
        "adapter_description": adapter.describe() if adapter else {},
        **manifest_policy,
        "credential_policy_safe": manifest_policy["credential_policy"] in SAFE_CREDENTIAL_POLICIES,
        "listener_policy_safe": manifest_policy["listener_policy"] in SAFE_LISTENER_POLICIES,
        "support_consistent": not (bool(module.get("supported")) and adapter_key == "unsupported"),
    }


def execute_adapter(
    *,
    run: dict[str, Any],
    path: RelayPath,
    operator: str,
    reason: str,
    audit_log: str,
    timebox_seconds: int,
    registry: AdapterRegistry | None = None,
) -> AdapterRunResult:
    module = dict(run["module"])
    adapter_key = str(module.get("adapter") or "unsupported")
    adapter_registry = registry or default_adapter_registry()
    adapter = adapter_registry.get(adapter_key)
    if adapter is None:
        outcome = AdapterOutcome(
            phase="dispatch",
            state="not_registered",
            reason=f"Adapter {adapter_key} is not registered in the RelayX execution adapter registry.",
        )
        return AdapterRunResult(
            result={
                "state": "adapter_not_registered",
                "reason": outcome.reason,
            },
            actions=[outcome.as_action(adapter_key)],
            lifecycle=[_lifecycle_row(outcome)],
        )
    context = build_adapter_context(
        run=run,
        path=path,
        operator=operator,
        reason=reason,
        audit_log=audit_log,
        timebox_seconds=timebox_seconds,
    )
    return adapter.run(context)


def sdk_guardrails(module: dict[str, Any], registry: AdapterRegistry | None = None) -> list[dict[str, Any]]:
    contract = adapter_contract_for_module(module, registry)
    return [
        {
            "key": "adapter_registered",
            "state": "pass" if contract["registered"] else "fail",
            "reason": (
                f"Adapter {contract['adapter']} is registered."
                if contract["registered"]
                else f"Adapter {contract['adapter']} is not registered."
            ),
        },
        {
            "key": "credential_policy",
            "state": "pass" if contract["credential_policy_safe"] else "fail",
            "reason": (
                f"Credential policy {contract['credential_policy']} is allowed by the SDK."
                if contract["credential_policy_safe"]
                else f"Credential policy {contract['credential_policy']} is not allowed by the SDK."
            ),
        },
        {
            "key": "listener_policy",
            "state": "pass" if contract["listener_policy_safe"] else "fail",
            "reason": (
                f"Listener policy {contract['listener_policy']} is allowed by the SDK."
                if contract["listener_policy_safe"]
                else f"Listener policy {contract['listener_policy']} is not allowed by the SDK."
            ),
        },
        {
            "key": "adapter_support_consistency",
            "state": "pass" if contract["support_consistent"] else "fail",
            "reason": (
                "Module support flag and adapter key are consistent."
                if contract["support_consistent"]
                else "A supported module cannot use the unsupported adapter boundary."
            ),
        },
    ]


def _lifecycle_row(outcome: AdapterOutcome) -> dict[str, Any]:
    row = {
        "phase": outcome.phase,
        "state": outcome.state,
        "reason": outcome.reason,
        "network_action": outcome.network_action,
    }
    if outcome.artifacts:
        row["artifacts"] = list(outcome.artifacts)
    if outcome.details:
        row["details"] = dict(outcome.details)
    return row


def _artifacts(outcomes: list[AdapterOutcome]) -> list[str]:
    rows: list[str] = []
    for outcome in outcomes:
        for artifact in outcome.artifacts:
            if artifact not in rows:
                rows.append(artifact)
    return rows
