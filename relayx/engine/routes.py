from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any

from ..models import Confidence, Evidence, EvidenceType, NoiseLevel, SourceAsset
from ..net import tcp_connect
from .operation_control import OperationControl, apply_start_throttle, expected_telemetry_for_operation, rollback_for_operation
from .scope import ScopePolicy
from .source import NOISE_RANK


ROUTE_AWARENESS_VERSION = 1

PIVOT_KIND_ALIASES = {
    "local": "direct",
    "same_segment": "direct",
    "ligolo-ng": "ligolo",
    "ligolo_ng": "ligolo",
    "sliver": "sliver_p2p",
    "sliver-p2p": "sliver_p2p",
    "socks5": "socks",
    "socks4": "socks",
    "tun": "tun2socks",
    "tun_to_socks": "tun2socks",
    "port_forward": "portfwd",
    "port-forward": "portfwd",
}

PIVOT_BASE_RISK = {
    "direct": 2.0,
    "ligolo": 8.0,
    "sliver_p2p": 14.0,
    "socks": 12.0,
    "tun2socks": 12.0,
    "portfwd": 10.0,
    "ssh": 8.0,
    "vpn": 7.0,
    "unknown": 16.0,
}

PIVOT_NOISE = {
    "direct": NoiseLevel.PASSIVE,
    "ligolo": NoiseLevel.LOW,
    "sliver_p2p": NoiseLevel.MEDIUM,
    "socks": NoiseLevel.MEDIUM,
    "tun2socks": NoiseLevel.MEDIUM,
    "portfwd": NoiseLevel.LOW,
    "ssh": NoiseLevel.LOW,
    "vpn": NoiseLevel.LOW,
    "unknown": NoiseLevel.MEDIUM,
}

RISK_LEVEL_SCORE = {
    "low": 4.0,
    "medium": 10.0,
    "high": 18.0,
    "critical": 28.0,
}


@dataclass(slots=True)
class RouteHop:
    index: int
    kind: str
    name: str = ""
    via: str = ""
    networks: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    risk_level: str = ""
    noise: NoiseLevel | None = None
    requires_listener: bool = False
    notes: list[str] = field(default_factory=list)
    source: str = "profile"

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "kind": self.kind,
            "name": self.name,
            "via": self.via,
            "networks": self.networks,
            "hosts": self.hosts,
            "risk_level": self.risk_level,
            "noise": self.noise.value if self.noise else "",
            "requires_listener": self.requires_listener,
            "notes": self.notes,
            "source": self.source,
        }


@dataclass(slots=True)
class RouteAssessment:
    source: str
    target: str
    target_protocol: str = ""
    target_port: int = 0
    reachable: bool = True
    state: str = "assumed_reachable"
    confidence: Confidence = Confidence.LOW
    hop_count: int = 0
    pivot_types: list[str] = field(default_factory=list)
    matched_hops: list[RouteHop] = field(default_factory=list)
    all_hops: list[RouteHop] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    noise: NoiseLevel = NoiseLevel.LOW
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": ROUTE_AWARENESS_VERSION,
            "source": self.source,
            "target": self.target,
            "target_protocol": self.target_protocol,
            "target_port": self.target_port,
            "reachable": self.reachable,
            "state": self.state,
            "confidence": self.confidence.value,
            "hop_count": self.hop_count,
            "pivot_types": self.pivot_types,
            "matched_hops": [hop.to_dict() for hop in self.matched_hops],
            "all_hops": [hop.to_dict() for hop in self.all_hops],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "noise": self.noise.value,
            "reasons": self.reasons,
            "limitations": self.limitations,
        }


def assess_route(
    source: SourceAsset,
    target: str,
    *,
    target_protocol: str = "",
    target_port: int = 0,
) -> RouteAssessment:
    hops = normalize_route_hops(source)
    if not hops:
        return RouteAssessment(
            source=source.host,
            target=target,
            target_protocol=target_protocol,
            target_port=target_port,
            reachable=True,
            state="assumed_reachable",
            confidence=Confidence.LOW,
            risk_score=24.0,
            risk_level="medium",
            noise=NoiseLevel.LOW,
            reasons=["No route profile was supplied; RelayX keeps the source path but marks route confidence low."],
            limitations=["Provide source subnets or route_hops to distinguish reachable, routed, and unreachable paths."],
        )

    matched = _matching_hops(hops, target)
    if matched:
        included = _chain_to(hops, matched[-1].index)
        direct = all(hop.kind == "direct" for hop in included)
        risk_score = _risk_score(included, matched=True, metadata_only=False)
        return RouteAssessment(
            source=source.host,
            target=target,
            target_protocol=target_protocol,
            target_port=target_port,
            reachable=True,
            state="direct" if direct else "routed",
            confidence=Confidence.HIGH,
            hop_count=len(included),
            pivot_types=_pivot_types(included),
            matched_hops=matched,
            all_hops=hops,
            risk_score=risk_score,
            risk_level=_risk_level(risk_score),
            noise=_max_noise(included),
            reasons=[
                f"Target matched explicit route metadata from {source.host}.",
                f"Matched route hop count is {len(included)}.",
            ],
            limitations=_route_limitations(included),
        )

    metadata_only = [hop for hop in hops if not hop.networks and not hop.hosts]
    if metadata_only:
        risk_score = _risk_score(metadata_only, matched=False, metadata_only=True)
        return RouteAssessment(
            source=source.host,
            target=target,
            target_protocol=target_protocol,
            target_port=target_port,
            reachable=True,
            state="metadata_only",
            confidence=Confidence.LOW,
            hop_count=len(metadata_only),
            pivot_types=_pivot_types(metadata_only),
            matched_hops=metadata_only,
            all_hops=hops,
            risk_score=risk_score,
            risk_level=_risk_level(risk_score),
            noise=_max_noise(metadata_only),
            reasons=["Route metadata exists but does not include a target CIDR or host constraint."],
            limitations=["RelayX cannot prove source-to-target reachability from unconstrained route labels."],
        )

    risk_score = _risk_score(hops, matched=False, metadata_only=False) + 20.0
    return RouteAssessment(
        source=source.host,
        target=target,
        target_protocol=target_protocol,
        target_port=target_port,
        reachable=False,
        state="unreachable",
        confidence=Confidence.MEDIUM,
        hop_count=len(hops),
        pivot_types=_pivot_types(hops),
        all_hops=hops,
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        noise=_max_noise(hops),
        reasons=["Structured route metadata did not match the target host or IP."],
        limitations=["Add a matching source subnet, reachable host, wildcard host, or pivot route before ranking this path as reachable."],
    )


def assess_route_matrix(
    sources: list[SourceAsset],
    targets: list[str],
    *,
    target_protocol: str = "",
    target_port: int = 0,
    scope: ScopePolicy | None = None,
    connect_check: bool = False,
    timeout: float = 3.0,
    operation_control: OperationControl | None = None,
) -> dict[str, Any]:
    rows = []
    control = operation_control or OperationControl()
    check_index = 0
    port = target_port or _default_port_for_protocol(target_protocol)
    for source in sorted(sources, key=lambda item: item.host):
        if scope and not scope.contains(source.host):
            rows.append(
                {
                    "source": source.host,
                    "state": "source_out_of_scope",
                    "reachable": False,
                    "reason": "Source is outside the supplied scope.",
                }
            )
            continue
        for target in sorted(targets):
            if scope and not scope.contains(target):
                rows.append(
                    {
                        "source": source.host,
                        "target": target,
                        "state": "target_out_of_scope",
                        "reachable": False,
                        "reason": "Target is outside the supplied scope.",
                    }
                )
                continue
            row = assess_route(source, target, target_protocol=target_protocol, target_port=port).to_dict()
            if connect_check:
                apply_start_throttle(control, check_index)
                row["reachability_check"] = _authorized_reachability_check(
                    target,
                    port=port,
                    timeout=timeout,
                    target_protocol=target_protocol,
                )
                check_index += 1
            rows.append(row)
    return {
        "name": "RelayX route awareness",
        "version": ROUTE_AWARENESS_VERSION,
        "target_protocol": target_protocol,
        "target_port": port,
        "source_count": len(sources),
        "target_count": len(targets),
        "connect_check": connect_check,
        "reachability_check": {
            "enabled": connect_check,
            "method": "authorized_direct_tcp_connect" if connect_check else "metadata_only",
            "network_action": "tcp_connect_check" if connect_check else "none",
            "expected_telemetry": expected_telemetry_for_operation(
                "routes",
                network_action="tcp_connect_check" if connect_check else "none",
                active_operation=connect_check,
            ),
            "rollback": rollback_for_operation(
                "routes",
                network_action="tcp_connect_check" if connect_check else "none",
                active_operation=connect_check,
            ),
        },
        "routes": rows,
    }


def normalize_route_hops(source: SourceAsset) -> list[RouteHop]:
    hops: list[RouteHop] = []
    if source.subnets:
        hops.append(
            RouteHop(
                index=1,
                kind="direct",
                name=source.segment or "source_segment",
                networks=_valid_networks(source.subnets),
                source="source.subnets",
            )
        )
    for raw in source.route_hops:
        hop = _hop_from_mapping(len(hops) + 1, raw)
        if hop:
            hops.append(hop)
    for route in source.routes:
        for hop in _hops_from_route_string(route, start=len(hops) + 1):
            hops.append(hop)
    return _renumber_hops(hops)


def route_evidence(assessment: RouteAssessment) -> list[Evidence]:
    raw = assessment.to_dict()
    return [
        Evidence(
            EvidenceType.INFERRED,
            "route_reachable",
            assessment.reachable,
            assessment.confidence,
            raw=raw,
            detail="Modeled source-to-target reachability from RelayX route and pivot metadata.",
        ),
        Evidence(
            EvidenceType.INFERRED,
            "route_reachability_state",
            assessment.state,
            assessment.confidence,
            raw=raw,
            detail="Route state: direct, routed, metadata_only, assumed_reachable, or unreachable.",
        ),
        Evidence(
            EvidenceType.INFERRED,
            "route_hop_count",
            assessment.hop_count,
            assessment.confidence,
            raw=raw,
            detail="Number of modeled route or pivot hops in the selected source path.",
        ),
        Evidence(
            EvidenceType.INFERRED,
            "route_pivot_types",
            assessment.pivot_types,
            assessment.confidence,
            raw=raw,
            detail="Normalized pivot mechanisms such as ligolo, socks, tun2socks, sliver_p2p, or portfwd.",
        ),
        Evidence(
            EvidenceType.INFERRED,
            "route_risk_score",
            assessment.risk_score,
            assessment.confidence,
            raw=raw,
            detail="Route-level OPSEC and complexity score used as an additional ranking penalty.",
        ),
        Evidence(
            EvidenceType.INFERRED,
            "route_risk_level",
            assessment.risk_level,
            assessment.confidence,
            raw=raw,
            detail="Route-level risk band derived from pivot count, pivot type, and route certainty.",
        ),
        Evidence(
            EvidenceType.INFERRED,
            "route_noise_level",
            assessment.noise.value,
            assessment.confidence,
            raw=raw,
            detail="Estimated OPSEC noise introduced by the route or pivot layer.",
        ),
    ]


def render_route_report(report: dict[str, Any]) -> str:
    routes = report.get("routes", [])
    if not routes:
        return "No route assessments available."
    lines = ["RelayX Route Awareness", ""]
    lines.append(f"Sources: {report.get('source_count', 0)}")
    lines.append(f"Targets: {report.get('target_count', 0)}")
    if report.get("target_protocol"):
        lines.append(f"Target protocol: {report['target_protocol']}")
    if report.get("connect_check"):
        lines.append("Reachability check: authorized direct TCP from operator runtime")
    lines.append("")
    for row in routes:
        source = row.get("source", "")
        target = row.get("target", "")
        state = row.get("state", "")
        if not target:
            lines.append(f"{source}: {state}")
            if row.get("reason"):
                lines.append(f"  {row['reason']}")
            continue
        lines.append(
            f"{source} -> {target}: {state} reachable={row.get('reachable')} "
            f"risk={row.get('risk_level', '-')} score={row.get('risk_score', '-')}"
        )
        if row.get("pivot_types"):
            lines.append(f"  pivots: {', '.join(row['pivot_types'])}")
        for reason in row.get("reasons", []):
            lines.append(f"  reason: {reason}")
        check = row.get("reachability_check")
        if check:
            lines.append(
                f"  reachability_check: {check.get('state')} "
                f"port={check.get('port')} method={check.get('method')}"
            )
            if check.get("reason"):
                lines.append(f"  check_reason: {check['reason']}")
        for limitation in row.get("limitations", []):
            lines.append(f"  limitation: {limitation}")
    return "\n".join(lines)


def route_report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def _hop_from_mapping(index: int, raw: dict[str, Any]) -> RouteHop | None:
    kind = _normalize_kind(raw.get("kind") or raw.get("type") or raw.get("transport") or raw.get("pivot") or "unknown")
    networks = _valid_networks(_listish(raw.get("networks") or raw.get("subnets") or raw.get("routes") or raw.get("cidrs")))
    hosts = _listish(raw.get("hosts") or raw.get("targets") or raw.get("reachable_hosts") or raw.get("host"))
    noise = _noise_value(raw.get("noise") or raw.get("noise_level"))
    return RouteHop(
        index=index,
        kind=kind,
        name=str(raw.get("name") or raw.get("id") or raw.get("session") or "").strip(),
        via=str(raw.get("via") or raw.get("parent") or "").strip(),
        networks=networks,
        hosts=hosts,
        risk_level=str(raw.get("risk") or raw.get("risk_level") or "").strip().lower(),
        noise=noise,
        requires_listener=_truthy(raw.get("requires_listener") or raw.get("listener") or raw.get("exposes_listener")),
        notes=_listish(raw.get("notes")),
        source="source.route_hops",
    )


def _hops_from_route_string(value: str, *, start: int) -> list[RouteHop]:
    hops: list[RouteHop] = []
    for offset, part in enumerate(re.split(r"\s*->\s*", value)):
        clean = part.strip()
        if not clean:
            continue
        hops.append(_hop_from_route_part(start + offset, clean))
    return hops


def _hop_from_route_part(index: int, value: str) -> RouteHop:
    fields = _key_value_route(value)
    if fields:
        kind = _normalize_kind(fields.get("kind") or fields.get("type") or fields.get("pivot") or fields.get("transport") or "unknown")
        return RouteHop(
            index=index,
            kind=kind,
            name=fields.get("name", ""),
            via=fields.get("via", ""),
            networks=_valid_networks(_listish(fields.get("net") or fields.get("network") or fields.get("networks") or fields.get("cidr"))),
            hosts=_listish(fields.get("host") or fields.get("hosts") or fields.get("target")),
            risk_level=fields.get("risk", ""),
            noise=_noise_value(fields.get("noise")),
            requires_listener=_truthy(fields.get("listener") or fields.get("requires_listener")),
            source="source.routes",
        )

    kind_part, target_part = _split_route_target(value)
    tokens = [token for token in re.split(r"[\s]+", target_part) if token]
    networks = _valid_networks(tokens + ([target_part] if target_part else []))
    hosts = [token for token in tokens if token not in networks and not _looks_like_network(token)]
    raw_kind, raw_name = _split_kind_name(kind_part)
    if not networks and _looks_like_network(value):
        raw_kind, raw_name = "direct", ""
        networks = _valid_networks([value])
    return RouteHop(
        index=index,
        kind=_normalize_kind(raw_kind),
        name=raw_name,
        networks=networks,
        hosts=hosts,
        source="source.routes",
    )


def _key_value_route(value: str) -> dict[str, str]:
    if "=" not in value:
        return {}
    fields: dict[str, str] = {}
    for part in re.split(r"[,;]\s*", value):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        fields[key.strip().lower()] = raw.strip()
    return fields


def _split_route_target(value: str) -> tuple[str, str]:
    if "@" in value:
        left, right = value.split("@", 1)
        return left.strip(), right.strip()
    pieces = value.split(":")
    if len(pieces) >= 3 and _looks_like_network(pieces[-1]):
        return ":".join(pieces[:-1]).strip(), pieces[-1].strip()
    return value, ""


def _split_kind_name(value: str) -> tuple[str, str]:
    if ":" in value:
        kind, name = value.split(":", 1)
        return kind.strip(), name.strip()
    if value:
        return value.strip(), ""
    return "unknown", ""


def _matching_hops(hops: list[RouteHop], target: str) -> list[RouteHop]:
    return [hop for hop in hops if _hop_matches(hop, target)]


def _hop_matches(hop: RouteHop, target: str) -> bool:
    target_ip = _target_ip(target)
    if target_ip is not None:
        for network in hop.networks:
            try:
                if target_ip in ip_network(network, strict=False):
                    return True
            except ValueError:
                continue
    target_name = target.lower()
    for host in hop.hosts:
        clean = host.lower()
        if clean in {"*", "any", "all"}:
            return True
        if clean == target_name:
            return True
        if clean.startswith("*.") and target_name.endswith(clean[1:]):
            return True
    return False


def _chain_to(hops: list[RouteHop], index: int) -> list[RouteHop]:
    return [hop for hop in hops if hop.index <= index]


def _pivot_types(hops: list[RouteHop]) -> list[str]:
    seen: set[str] = set()
    rows: list[str] = []
    for hop in hops:
        if hop.kind not in seen:
            rows.append(hop.kind)
            seen.add(hop.kind)
    return rows


def _risk_score(hops: list[RouteHop], *, matched: bool, metadata_only: bool) -> float:
    score = 0.0
    for hop in hops:
        score += PIVOT_BASE_RISK.get(hop.kind, PIVOT_BASE_RISK["unknown"])
        score += RISK_LEVEL_SCORE.get(hop.risk_level, 0.0)
        if hop.requires_listener:
            score += 12.0
    if len(hops) > 1:
        score += (len(hops) - 1) * 6.0
    if metadata_only:
        score += 16.0
    if not matched:
        score += 6.0
    return round(score, 2)


def _risk_level(score: float) -> str:
    if score >= 60:
        return "critical"
    if score >= 38:
        return "high"
    if score >= 18:
        return "medium"
    return "low"


def _max_noise(hops: list[RouteHop]) -> NoiseLevel:
    value = NoiseLevel.PASSIVE
    for hop in hops:
        noise = hop.noise or PIVOT_NOISE.get(hop.kind, NoiseLevel.MEDIUM)
        if NOISE_RANK[noise] > NOISE_RANK[value]:
            value = noise
    return value


def _route_limitations(hops: list[RouteHop]) -> list[str]:
    limitations: list[str] = []
    if any(hop.requires_listener for hop in hops):
        limitations.append("At least one route hop depends on an operator-controlled listener or exposed pivot service.")
    if any(hop.kind in {"socks", "tun2socks", "sliver_p2p"} for hop in hops):
        limitations.append("Session-backed pivots can change during an operation; re-check reachability before execution.")
    return limitations


def _valid_networks(values: list[str]) -> list[str]:
    networks: list[str] = []
    for value in values:
        clean = value.strip()
        if not clean:
            continue
        try:
            networks.append(str(ip_network(clean, strict=False)))
        except ValueError:
            continue
    return sorted(set(networks))


def _target_ip(value: str):
    try:
        return ip_address(value)
    except ValueError:
        return None


def _looks_like_network(value: str) -> bool:
    try:
        ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _normalize_kind(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_") or "unknown"
    return PIVOT_KIND_ALIASES.get(text, text)


def _noise_value(value: Any) -> NoiseLevel | None:
    if value in (None, ""):
        return None
    try:
        return NoiseLevel(str(value).strip().lower())
    except ValueError:
        return None


def _renumber_hops(hops: list[RouteHop]) -> list[RouteHop]:
    for index, hop in enumerate(hops, start=1):
        hop.index = index
    return hops


def _authorized_reachability_check(
    target: str,
    *,
    port: int,
    timeout: float,
    target_protocol: str,
) -> dict[str, Any]:
    if port <= 0:
        return {
            "authorized": True,
            "method": "authorized_direct_tcp_connect",
            "network_action": "tcp_connect_check",
            "target": target,
            "port": 0,
            "target_protocol": target_protocol,
            "state": "skipped",
            "open": False,
            "reason": "Target port is unknown; supply --target-port or --target-protocol.",
            "limitations": [
                "This check never opens a pivot session and cannot prove session-backed route availability.",
            ],
            "expected_telemetry": expected_telemetry_for_operation(
                "routes",
                network_action="tcp_connect_check",
                active_operation=True,
            ),
            "rollback": rollback_for_operation(
                "routes",
                network_action="tcp_connect_check",
                active_operation=True,
            ),
        }
    result = tcp_connect(target, port, timeout=timeout)
    return {
        "authorized": True,
        "method": "authorized_direct_tcp_connect",
        "network_action": "tcp_connect_check",
        "target": target,
        "port": port,
        "target_protocol": target_protocol,
        "state": "open" if result.open else "closed",
        "open": result.open,
        "error": result.error,
        "reason": (
            "TCP reachability was observed from the operator runtime."
            if result.open
            else "TCP reachability was not observed from the operator runtime."
        ),
        "limitations": [
            "This validates an authorized direct TCP observation only; it does not start or prove a pivot session.",
            "For session-backed routes, treat this as endpoint availability context rather than source-to-target proof.",
        ],
        "expected_telemetry": expected_telemetry_for_operation(
            "routes",
            network_action="tcp_connect_check",
            active_operation=True,
        ),
        "rollback": rollback_for_operation(
            "routes",
            network_action="tcp_connect_check",
            active_operation=True,
        ),
    }


def _default_port_for_protocol(protocol: str) -> int:
    clean = protocol.strip().lower()
    return {
        "smb": 445,
        "ldap": 389,
        "ldaps": 636,
        "http": 80,
        "https": 443,
        "mssql": 1433,
    }.get(clean, 0)


def _listish(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value in (None, ""):
        return []
    return [part.strip() for part in str(value).replace(";", ",").split(",") if part.strip()]


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}
