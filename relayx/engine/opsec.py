from __future__ import annotations

from ..models import RelayPath
from .calculus import assess_path
from .evidence import evidence_value
from .risk import estimate_noise


def build_dry_run_plan(path: RelayPath) -> dict:
    assessment = assess_path(path)
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    telemetry = expected_telemetry(path)
    rollback = rollback_steps(path)
    return {
        "path_id": path.id,
        "status": path.status.value,
        "decision": assessment.decision,
        "score": path.score,
        "impact": path.impact.value,
        "confidence": path.confidence.value,
        "source": path.source,
        "target": path.target,
        "transport": path.transport,
        "target_service": path.target_service,
        "source_capability": source_capability,
        "noise": estimate_noise(path).value,
        "rule_id": assessment.rule_id,
        "target_family": assessment.target_family,
        "preconditions": assessment.preconditions,
        "hardening_gates": [gate.as_dict() for gate in assessment.gates],
        "expected_telemetry": telemetry,
        "rollback": rollback,
        "operator_guardrails": [
            "Confirm written authorization and exact source/target scope.",
            "Run one path at a time with explicit timestamps and owner.",
            "Do not execute relay or coercion from this dry-run plan alone.",
            "Stop if telemetry deviates from the expected single-path pattern.",
        ],
        "execution": {
            "supported": False,
            "reason": "RelayX dry-run plans do not execute relay operations; use relayx run for guarded execution records. Live relay modules are not enabled by default.",
        },
    }


def expected_telemetry(path: RelayPath) -> list[str]:
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    target = path.target_service.lower()
    telemetry = [
        "RelayX result file and operator activity log entry.",
        "Target-side connection attempts for the assessed protocol.",
    ]
    if source_capability == "webclient":
        telemetry.extend(
            [
                "Source-side WebClient service activity.",
                "Outbound HTTP/WebDAV authentication attempt from the source if actively validated.",
            ]
        )
    elif source_capability in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        telemetry.extend(
            [
                "Source-side RPC service access telemetry if actively validated.",
                "Outbound NTLM authentication from the source to the operator-controlled listener.",
            ]
        )
    elif source_capability == "mssql_outbound":
        telemetry.extend(
            [
                "SQL Server audit or default trace entries if outbound authentication is actively validated.",
                "Outbound SMB/HTTP authentication from the SQL Server service account context.",
            ]
        )
    elif source_capability == "name_resolution":
        telemetry.extend(
            [
                "Name registration or resolution telemetry for ADIDNS/SPN/LLMNR/NBNS changes.",
                "Rollback evidence for any operator-created name.",
            ]
        )
    if "ldap" in target:
        telemetry.append("Domain controller LDAP bind telemetry and possible failed authentication events.")
    if "http" in target:
        telemetry.append("Web server authentication logs and possible 401/403 challenge-flow records.")
    if "mssql" in target:
        telemetry.append("SQL Server login telemetry and possible failed login records.")
    if "smb" in target:
        telemetry.append("SMB session setup or negotiate telemetry on the target.")
    return telemetry


def rollback_steps(path: RelayPath) -> list[str]:
    source_capability = str(evidence_value(path, "source_capability", "generic"))
    steps = [
        "Preserve RelayX evidence and timestamps before changing state.",
        "Notify blue-team or change owner if agreed in rules of engagement.",
    ]
    if source_capability == "name_resolution":
        steps.append("Remove any operator-created DNS/SPN/name-resolution record and verify deletion.")
    if source_capability == "webclient":
        steps.append("Stop any operator-controlled WebDAV listener used during validation.")
    if source_capability in {"spooler", "efsrpc", "dfsnm", "fsrvp"}:
        steps.append("Confirm no long-running RPC validation process or callback listener remains.")
    if source_capability == "mssql_outbound":
        steps.append("Confirm no SQL job, procedure call, or linked-server test artifact remains.")
    return steps
