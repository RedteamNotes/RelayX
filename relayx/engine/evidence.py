from __future__ import annotations

from typing import Any

from ..models import Evidence, RelayPath


def evidence_value(path: RelayPath, key: str, default: Any = None) -> Any:
    for evidence in path.evidence:
        if evidence.key == key:
            return evidence.value
    return default


def evidence_raw(path: RelayPath, key: str) -> dict:
    for evidence in path.evidence:
        if evidence.key == key:
            return evidence.raw
    return {}


def has_evidence(path: RelayPath, key: str, value: Any = None) -> bool:
    for evidence in path.evidence:
        if evidence.key != key:
            continue
        return True if value is None else evidence.value == value
    return False


def upsert_evidence(path: RelayPath, item: Evidence) -> None:
    for index, existing in enumerate(path.evidence):
        if existing.key == item.key:
            path.evidence[index] = item
            return
    path.evidence.append(item)
