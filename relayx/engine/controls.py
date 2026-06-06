from __future__ import annotations

from collections import defaultdict

from ..models import RelayPath
from .evidence import evidence_value


CONTROL_LABELS = {
    "adcs_hardening": "AD CS web enrollment hardening",
    "credential_boundary": "Credential boundary and tiering",
    "http_epa": "HTTP Extended Protection for Authentication",
    "ldap_channel_binding": "LDAP channel binding",
    "ldap_signing": "LDAP signing",
    "mssql_epa": "MSSQL Extended Protection for Authentication",
    "mssql_service_account_hardening": "MSSQL service account hardening",
    "name_resolution_hardening": "Name-resolution hardening",
    "ntlm_restriction": "NTLM restriction and monitoring",
    "outbound_auth_egress": "Outbound authentication egress control",
    "rpc_coercion_reduction": "RPC coercion surface reduction",
    "smb_signing": "SMB signing",
    "webclient_hardening": "WebClient/WebDAV hardening",
}


def control_summary(paths: list[RelayPath]) -> list[dict]:
    rows: dict[str, dict] = {}
    path_ids: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        controls = evidence_value(path, "relayx_controls", []) or []
        for control in controls:
            path_ids[str(control)].add(path.id)
            row = rows.setdefault(
                str(control),
                {
                    "control": str(control),
                    "label": CONTROL_LABELS.get(str(control), str(control).replace("_", " ").title()),
                    "paths": 0,
                    "cumulative_score": 0.0,
                    "max_impact": "info",
                },
            )
            row["cumulative_score"] += path.score
            row["max_impact"] = _max_impact(row["max_impact"], path.impact.value)
    for control, row in rows.items():
        row["paths"] = len(path_ids[control])
        row["path_ids"] = sorted(path_ids[control])
        row["cumulative_score"] = round(row["cumulative_score"], 2)
    return sorted(
        rows.values(),
        key=lambda item: (item["cumulative_score"], item["paths"], item["control"]),
        reverse=True,
    )


def _max_impact(left: str, right: str) -> str:
    order = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return left if order[left] >= order[right] else right
