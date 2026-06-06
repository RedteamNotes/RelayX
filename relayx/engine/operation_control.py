from __future__ import annotations

import random
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any


OPERATION_CONTROL_VERSION = 1
MACHINE_CLEAN_FORMATS = ("json", "csv", "jsonl", "html", "markdown", "mermaid", "opengraph")


class OperationControlError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class OperationControl:
    rate_limit_per_minute: int = 0
    delay_seconds: float = 0.0
    jitter_seconds: float = 0.0
    start_after: str = ""
    stop_before: str = ""

    @classmethod
    def from_values(
        cls,
        *,
        rate_limit_per_minute: int | str | None = None,
        delay_seconds: float | str | None = None,
        jitter_seconds: float | str | None = None,
        start_after: str | None = None,
        stop_before: str | None = None,
    ) -> "OperationControl":
        return cls(
            rate_limit_per_minute=max(0, _int_value(rate_limit_per_minute)),
            delay_seconds=max(0.0, _float_value(delay_seconds)),
            jitter_seconds=max(0.0, _float_value(jitter_seconds)),
            start_after=str(start_after or "").strip(),
            stop_before=str(stop_before or "").strip(),
        )

    @property
    def configured(self) -> bool:
        return any(
            (
                self.rate_limit_per_minute > 0,
                self.delay_seconds > 0,
                self.jitter_seconds > 0,
                bool(self.start_after),
                bool(self.stop_before),
            )
        )

    def effective_spacing_seconds(self) -> float:
        if self.rate_limit_per_minute <= 0:
            return self.delay_seconds
        return max(self.delay_seconds, 60.0 / float(self.rate_limit_per_minute))

    def report(
        self,
        *,
        operation: str,
        active_operation: bool,
        action_count: int = 0,
        network_action: str = "none",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        return {
            "version": OPERATION_CONTROL_VERSION,
            "operation": operation,
            "active_operation": active_operation,
            "network_action": network_action,
            "action_count": max(0, int(action_count)),
            "configured": self.configured,
            "rate_limit": {
                "max_per_minute": self.rate_limit_per_minute,
                "delay_seconds": self.delay_seconds,
                "jitter_seconds": self.jitter_seconds,
                "effective_spacing_seconds": round(self.effective_spacing_seconds(), 3),
            },
            "schedule": operation_window_report(
                start_after=self.start_after,
                stop_before=self.stop_before,
                now=now,
            ),
            "machine_output": {
                "clean_formats_by_default": list(MACHINE_CLEAN_FORMATS),
                "banner_suppressed_for_machine_formats": True,
            },
            "expected_telemetry": expected_telemetry_for_operation(
                operation,
                network_action=network_action,
                active_operation=active_operation,
            ),
            "rollback": rollback_for_operation(
                operation,
                network_action=network_action,
                active_operation=active_operation,
            ),
        }


def operation_window_report(
    *,
    start_after: str = "",
    stop_before: str = "",
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now().astimezone()
    start = _parse_datetime(start_after, now)
    stop = _parse_datetime(stop_before, now)
    if start["error"] or stop["error"]:
        return {
            "state": "invalid",
            "start_after": start_after,
            "stop_before": stop_before,
            "now": now.isoformat(),
            "reason": start["error"] or stop["error"],
        }
    start_dt = start["value"]
    stop_dt = stop["value"]
    if start_dt and stop_dt and stop_dt < start_dt:
        return {
            "state": "invalid",
            "start_after": start_after,
            "stop_before": stop_before,
            "now": now.isoformat(),
            "reason": "stop-before must be later than start-after.",
        }
    if start_dt and now < start_dt:
        return {
            "state": "not_started",
            "start_after": start_after,
            "stop_before": stop_before,
            "now": now.isoformat(),
            "reason": f"Operation window starts at {start_dt.isoformat()}.",
        }
    if stop_dt and now > stop_dt:
        return {
            "state": "expired",
            "start_after": start_after,
            "stop_before": stop_before,
            "now": now.isoformat(),
            "reason": f"Operation window ended at {stop_dt.isoformat()}.",
        }
    if start_dt or stop_dt:
        return {
            "state": "ready",
            "start_after": start_after,
            "stop_before": stop_before,
            "now": now.isoformat(),
            "reason": "Current time is inside the configured operation window.",
        }
    return {
        "state": "not_configured",
        "start_after": "",
        "stop_before": "",
        "now": now.isoformat(),
        "reason": "No operation window was configured.",
    }


def operation_control_guardrails(report: dict[str, Any]) -> list[dict[str, str]]:
    schedule = report.get("schedule") or {}
    schedule_state = str(schedule.get("state") or "not_configured")
    active = bool(report.get("active_operation"))
    guardrails = [
        {
            "key": "operation_rate_limit",
            "state": "pass",
            "reason": _rate_limit_reason(report.get("rate_limit") or {}),
        }
    ]
    if schedule_state in {"not_configured", "ready"}:
        state = "pass"
    elif active:
        state = "fail"
    else:
        state = "warn"
    guardrails.append(
        {
            "key": "operation_window",
            "state": state,
            "reason": str(schedule.get("reason") or "Operation window evaluated."),
        }
    )
    guardrails.append(
        {
            "key": "machine_output_clean",
            "state": "pass",
            "reason": "Machine-readable exports remain banner-free and stable by default.",
        }
    )
    return guardrails


def enforce_operation_window(report: dict[str, Any]) -> tuple[bool, str]:
    schedule = report.get("schedule") or {}
    state = str(schedule.get("state") or "not_configured")
    if state in {"not_configured", "ready"}:
        return True, str(schedule.get("reason") or "Operation window is ready.")
    return False, str(schedule.get("reason") or f"Operation window state is {state}.")


def apply_start_throttle(control: OperationControl, index: int) -> float:
    ensure_operation_window(control)
    delay = control.effective_spacing_seconds()
    if index <= 0 or delay <= 0:
        return 0.0
    if control.jitter_seconds > 0:
        delay += random.uniform(0.0, control.jitter_seconds)
    time.sleep(delay)
    ensure_operation_window(control)
    return delay


def initial_delay_seconds(control: OperationControl) -> float:
    if control.delay_seconds > 0:
        jitter = random.uniform(0.0, control.jitter_seconds) if control.jitter_seconds > 0 else 0.0
        return control.delay_seconds + jitter
    return 0.0


def ensure_operation_window(control: OperationControl) -> None:
    report = control.report(operation="runtime", active_operation=True, network_action="scheduled_start")
    ok, reason = enforce_operation_window(report)
    if not ok:
        raise OperationControlError(reason)


def unique_strings(*groups: list[str] | tuple[str, ...]) -> list[str]:
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


def expected_telemetry_for_operation(
    operation: str,
    *,
    network_action: str,
    active_operation: bool,
) -> list[str]:
    telemetry = [f"RelayX {operation} artifact with OPSEC controls and timestamps."]
    if network_action == "target_assessment":
        telemetry.append("Target-side TCP connection and NTLM challenge-flow telemetry for assessed services.")
    elif network_action == "target_reprobe":
        telemetry.append("Target service logs for a single target-side protocol reprobe.")
    elif network_action == "tcp_connect_check":
        telemetry.append("Operator-runtime TCP connect telemetry for the explicitly requested reachability check.")
    elif network_action == "offline_audit_record":
        telemetry.append("RelayX JSONL audit entry; no network telemetry is expected from the offline adapter.")
    if active_operation:
        telemetry.append("Operator audit timeline covering start, stop, target count, rate limits, and configured time window.")
    return telemetry


def rollback_for_operation(
    operation: str,
    *,
    network_action: str,
    active_operation: bool,
) -> list[str]:
    rollback = [f"Preserve the RelayX {operation} artifact and audit timestamps."]
    if network_action in {"target_assessment", "target_reprobe", "tcp_connect_check"}:
        rollback.append("Stop any remaining probe attempts when the timebox or stop-before window is reached.")
    if network_action == "offline_audit_record":
        rollback.append("No network listener, credential handler, or relay session was started by this operation.")
    if active_operation:
        rollback.append("Notify stakeholders if expected telemetry differs from the approved operation plan.")
    return rollback


def _rate_limit_reason(data: dict[str, Any]) -> str:
    max_per_minute = int(data.get("max_per_minute") or 0)
    delay = float(data.get("delay_seconds") or 0)
    jitter = float(data.get("jitter_seconds") or 0)
    spacing = float(data.get("effective_spacing_seconds") or 0)
    if max_per_minute <= 0 and delay <= 0 and jitter <= 0:
        return "No explicit rate limit was configured."
    return (
        f"Start spacing is {spacing:.3f}s "
        f"(rate_limit_per_minute={max_per_minute}, delay={delay:.3f}s, jitter={jitter:.3f}s)."
    )


def _parse_datetime(value: str, now: datetime) -> dict[str, Any]:
    text = str(value or "").strip()
    if not text:
        return {"value": None, "error": ""}
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return {"value": None, "error": f"Invalid ISO-8601 datetime: {text}."}
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=now.tzinfo)
    return {"value": parsed.astimezone(now.tzinfo), "error": ""}


def _int_value(value: int | str | None) -> int:
    if value in (None, ""):
        return 0
    return int(value)


def _float_value(value: float | str | None) -> float:
    if value in (None, ""):
        return 0.0
    return float(value)
