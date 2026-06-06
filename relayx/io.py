from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import NoiseLevel, ScanResult, SourceAsset, scan_result_from_plain, to_plain


def load_targets(value: str | None) -> list[str]:
    if not value:
        return []
    path = Path(value)
    if path.exists():
        targets: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            clean = line.split("#", 1)[0].strip()
            if clean:
                targets.append(clean)
        return targets
    targets = []
    for part in value.split(","):
        clean = part.strip()
        if clean:
            targets.append(clean)
    return targets


def load_sources(value: str | None) -> list[SourceAsset]:
    if not value:
        return []
    path = Path(value)
    if not path.exists():
        return [SourceAsset(host=part.strip()) for part in value.split(",") if part.strip()]
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("sources", data) if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise ValueError("source JSON must be a list or an object with a 'sources' list")
        return [_source_from_mapping(row) for row in rows]
    with path.open("r", encoding="utf-8", newline="") as handle:
        sample = handle.read(2048)
        handle.seek(0)
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        if "," in first_line:
            return [_source_from_mapping(row) for row in csv.DictReader(handle)]
        return [
            SourceAsset(host=line.split("#", 1)[0].strip())
            for line in handle
            if line.split("#", 1)[0].strip()
        ]


def _source_from_mapping(row: dict) -> SourceAsset:
    host = str(row.get("host") or row.get("name") or "").strip()
    if not host:
        raise ValueError("source entry is missing host")
    capabilities = row.get("capabilities")
    if not isinstance(capabilities, dict):
        capabilities = {}
    normalized = {str(key): _truthy(value) for key, value in capabilities.items()}
    for key in [
        "webclient",
        "webdav",
        "spooler",
        "efsrpc",
        "dfsnm",
        "fsrvp",
        "mssql_outbound",
        "adidns",
        "ghost_spn",
        "name_resolution",
    ]:
        if key in row:
            normalized[key] = _truthy(row[key])
    if normalized.get("webdav"):
        normalized["webclient"] = True
    if normalized.get("adidns") or normalized.get("ghost_spn"):
        normalized["name_resolution"] = True
    tags = _listish(row.get("tags", []))
    routes = _listish(row.get("routes", []))
    notes = _listish(row.get("notes", []))
    route_hops = _route_hops(row.get("route_hops") or row.get("pivots") or row.get("hops"))
    subnets = _listish(row.get("subnets") or row.get("networks") or [])
    session = str(row.get("session") or row.get("session_id") or "").strip()
    segment = str(row.get("segment") or "").strip()
    noise = str(row.get("noise_limit") or row.get("max_noise") or NoiseLevel.HIGH.value).lower()
    return SourceAsset(
        host=host,
        capabilities=normalized,
        tags=tags,
        routes=routes,
        route_hops=route_hops,
        subnets=subnets,
        session=session,
        segment=segment,
        noise_limit=NoiseLevel(noise),
        notes=notes,
    )


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}


def _listish(value) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    return [part.strip() for part in str(value).replace(";", ",").split(",") if part.strip()]


def _route_hops(value) -> list[dict]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [dict(value)]
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, list):
        return [dict(item) for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        return [dict(parsed)]
    return []


def write_result(result: ScanResult, path: str) -> None:
    data = to_plain(result)
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def read_result(path: str) -> ScanResult:
    result_path = Path(path)
    if not result_path.exists():
        raise ValueError(f"RelayX result file does not exist: {path}")
    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"RelayX result file {path} is not valid JSON: {exc.msg}") from exc
    return scan_result_from_plain(data)
