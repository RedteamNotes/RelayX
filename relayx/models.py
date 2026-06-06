from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from . import __version__


class Status(str, Enum):
    RELAYABLE = "relayable"
    BLOCKED = "blocked"
    CANDIDATE = "candidate"
    UNKNOWN = "unknown"
    ERROR = "error"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EvidenceType(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class NoiseLevel(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Impact(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Evidence:
    type: EvidenceType
    key: str
    value: Any
    confidence: Confidence = Confidence.UNKNOWN
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    host: str
    port: int
    protocol: str
    name: str
    status: Status
    confidence: Confidence
    impact: Impact = Impact.INFO
    summary: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    opsec_notes: list[str] = field(default_factory=list)
    error: str = ""


@dataclass(slots=True)
class SourceAsset:
    host: str
    capabilities: dict[str, bool] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    route_hops: list[dict[str, Any]] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)
    session: str = ""
    segment: str = ""
    noise_limit: NoiseLevel = NoiseLevel.HIGH
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RelayPath:
    id: str
    source: str
    transport: str
    target: str
    target_service: str
    status: Status
    impact: Impact
    confidence: Confidence
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    opsec_notes: list[str] = field(default_factory=list)
    score: float = 0.0


@dataclass(slots=True)
class ScanMetadata:
    tool: str = "RelayX"
    version: str = __version__
    schema_version: int = 1
    started_at: str = ""
    finished_at: str = ""
    mode: str = "readiness"
    active: bool = False
    target_count: int = 0
    source_count: int = 0
    operation_control: dict[str, Any] = field(default_factory=dict)
    expected_telemetry: list[str] = field(default_factory=list)
    rollback: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    metadata: ScanMetadata
    findings: list[Finding] = field(default_factory=list)
    paths: list[RelayPath] = field(default_factory=list)
    sources: list[SourceAsset] = field(default_factory=list)

    @classmethod
    def new(cls, target_count: int, active: bool = False, source_count: int = 0) -> "ScanResult":
        now = datetime.now(UTC).isoformat()
        return cls(
            metadata=ScanMetadata(
                started_at=now,
                finished_at="",
                active=active,
                target_count=target_count,
                source_count=source_count,
            )
        )

    def finish(self) -> None:
        self.metadata.finished_at = datetime.now(UTC).isoformat()


def to_plain(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [to_plain(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    return obj


def evidence_from_plain(data: dict[str, Any]) -> Evidence:
    return Evidence(
        type=EvidenceType(data.get("type", EvidenceType.OBSERVED.value)),
        key=data.get("key", ""),
        value=data.get("value"),
        confidence=Confidence(data.get("confidence", Confidence.UNKNOWN.value)),
        detail=data.get("detail", ""),
        raw=data.get("raw") or {},
    )


def finding_from_plain(data: dict[str, Any]) -> Finding:
    return Finding(
        host=data.get("host", ""),
        port=int(data.get("port", 0)),
        protocol=data.get("protocol", ""),
        name=data.get("name", ""),
        status=Status(data.get("status", Status.UNKNOWN.value)),
        confidence=Confidence(data.get("confidence", Confidence.UNKNOWN.value)),
        impact=Impact(data.get("impact", Impact.INFO.value)),
        summary=data.get("summary", ""),
        evidence=[evidence_from_plain(e) for e in data.get("evidence", [])],
        blockers=list(data.get("blockers", [])),
        fixes=list(data.get("fixes", [])),
        opsec_notes=list(data.get("opsec_notes", [])),
        error=data.get("error", ""),
    )


def source_from_plain(data: dict[str, Any]) -> SourceAsset:
    noise = data.get("noise_limit", NoiseLevel.HIGH.value)
    return SourceAsset(
        host=data.get("host", ""),
        capabilities={str(k): bool(v) for k, v in (data.get("capabilities") or {}).items()},
        tags=list(data.get("tags", [])),
        routes=list(data.get("routes", [])),
        route_hops=[
            dict(item)
            for item in data.get("route_hops", [])
            if isinstance(item, dict)
        ],
        subnets=list(data.get("subnets", [])),
        session=data.get("session", "") or data.get("session_id", ""),
        segment=data.get("segment", ""),
        noise_limit=NoiseLevel(noise),
        notes=list(data.get("notes", [])),
    )


def path_from_plain(data: dict[str, Any]) -> RelayPath:
    return RelayPath(
        id=data.get("id", ""),
        source=data.get("source", ""),
        transport=data.get("transport", ""),
        target=data.get("target", ""),
        target_service=data.get("target_service", ""),
        status=Status(data.get("status", Status.UNKNOWN.value)),
        impact=Impact(data.get("impact", Impact.INFO.value)),
        confidence=Confidence(data.get("confidence", Confidence.UNKNOWN.value)),
        summary=data.get("summary", ""),
        evidence=[evidence_from_plain(e) for e in data.get("evidence", [])],
        blockers=list(data.get("blockers", [])),
        fixes=list(data.get("fixes", [])),
        opsec_notes=list(data.get("opsec_notes", [])),
        score=float(data.get("score", 0.0)),
    )


def scan_result_from_plain(data: dict[str, Any]) -> ScanResult:
    meta_data = data.get("metadata") or {}
    result = ScanResult(
        metadata=ScanMetadata(
            tool=meta_data.get("tool", "RelayX"),
            version=meta_data.get("version", __version__),
            schema_version=int(meta_data.get("schema_version", 1)),
            started_at=meta_data.get("started_at", ""),
            finished_at=meta_data.get("finished_at", ""),
            mode=meta_data.get("mode", "readiness"),
            active=bool(meta_data.get("active", False)),
            target_count=int(meta_data.get("target_count", 0)),
            source_count=int(meta_data.get("source_count", 0)),
            operation_control=dict(meta_data.get("operation_control") or {}),
            expected_telemetry=list(meta_data.get("expected_telemetry") or []),
            rollback=list(meta_data.get("rollback") or []),
        ),
        findings=[finding_from_plain(f) for f in data.get("findings", [])],
        paths=[path_from_plain(p) for p in data.get("paths", [])],
        sources=[source_from_plain(s) for s in data.get("sources", [])],
    )
    return result
