from __future__ import annotations

from collections import defaultdict

from ..models import Confidence, Evidence, EvidenceType, Finding, Impact, NoiseLevel, RelayPath, SourceAsset, Status
from .calculus import annotate_paths
from .routes import assess_route, route_evidence
from .scope import ScopePolicy
from .risk import score_path
from .source import SourceCapabilitySpec, compatible_source_capabilities


def _combine_confidence(findings: list[Finding]) -> Confidence:
    if not findings:
        return Confidence.UNKNOWN
    values = [f.confidence for f in findings]
    if all(v == Confidence.HIGH for v in values):
        return Confidence.HIGH
    if any(v == Confidence.MEDIUM for v in values) or any(v == Confidence.HIGH for v in values):
        return Confidence.MEDIUM
    return Confidence.LOW


def _path_id(index: int) -> str:
    return f"PX-{index:04d}"


def build_paths(
    findings: list[Finding],
    sources: list[SourceAsset] | None = None,
    max_noise: NoiseLevel | None = None,
    scope: ScopePolicy | None = None,
) -> list[RelayPath]:
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_host[finding.host].append(finding)

    paths: list[RelayPath] = []
    index = 1

    for host, host_findings in sorted(by_host.items()):
        smb_findings = [f for f in host_findings if f.protocol == "smb" and f.name == "smb_signing"]
        for finding in smb_findings:
            if finding.status == Status.RELAYABLE:
                path = RelayPath(
                    id=_path_id(index),
                    source="external_or_internal_ntlm_source",
                    transport="SMB",
                    target=host,
                    target_service="SMB/445",
                    status=Status.CANDIDATE,
                    impact=Impact.MEDIUM,
                    confidence=finding.confidence,
                    summary="SMB target does not require signing and is a relay candidate.",
                    evidence=finding.evidence,
                    blockers=[],
                    fixes=finding.fixes,
                    opsec_notes=[
                        "Target readiness only; source coercion and credential context are not validated.",
                        *finding.opsec_notes,
                    ],
                )
                path.score = score_path(path)
                paths.append(path)
                index += 1
            elif finding.status == Status.BLOCKED:
                path = RelayPath(
                    id=_path_id(index),
                    source="external_or_internal_ntlm_source",
                    transport="SMB",
                    target=host,
                    target_service="SMB/445",
                    status=Status.BLOCKED,
                    impact=Impact.INFO,
                    confidence=finding.confidence,
                    summary="SMB relay is blocked by required signing.",
                    evidence=finding.evidence,
                    blockers=finding.blockers,
                    fixes=finding.fixes,
                    opsec_notes=finding.opsec_notes,
                )
                path.score = score_path(path)
                paths.append(path)
                index += 1

        http_candidates = [
            f
            for f in host_findings
            if f.protocol in {"http", "https"}
            and f.status in {Status.CANDIDATE, Status.RELAYABLE}
            and f.name in {"http_ntlm_endpoint", "adcs_web_enrollment", "winrm_http_ntlm"}
        ]
        for finding in http_candidates:
            target_service = f"{finding.protocol.upper()}/{finding.port}"
            if finding.name == "adcs_web_enrollment":
                target_service += " /certsrv"
            elif finding.name == "winrm_http_ntlm":
                target_service += " /wsman"
            path = RelayPath(
                id=_path_id(index),
                source="webdav_or_http_ntlm_source",
                transport="HTTP/NTLM",
                target=host,
                target_service=target_service,
                status=Status.CANDIDATE,
                impact=finding.impact,
                confidence=finding.confidence,
                summary=finding.summary,
                evidence=finding.evidence,
                blockers=finding.blockers,
                fixes=finding.fixes,
                opsec_notes=[
                    "Treat as candidate until EPA/CBT behavior is calibrated for this exact endpoint.",
                    *finding.opsec_notes,
                ],
            )
            path.score = score_path(path)
            paths.append(path)
            index += 1

        ldap_findings = [f for f in host_findings if f.protocol in {"ldap", "ldaps"}]
        for finding in ldap_findings:
            path = RelayPath(
                id=_path_id(index),
                source="external_or_internal_ntlm_source",
                transport=finding.protocol.upper(),
                target=host,
                target_service=f"{finding.protocol.upper()}/{finding.port}",
                status=finding.status,
                impact=Impact.MEDIUM,
                confidence=_combine_confidence([finding]),
                summary=finding.summary,
                evidence=finding.evidence,
                blockers=finding.blockers,
                fixes=finding.fixes,
                opsec_notes=finding.opsec_notes,
            )
            path.score = score_path(path)
            paths.append(path)
            index += 1

        mssql_findings = [f for f in host_findings if f.protocol == "mssql"]
        for finding in mssql_findings:
            path = RelayPath(
                id=_path_id(index),
                source="mssql_or_coercible_ntlm_source",
                transport="MSSQL/NTLM",
                target=host,
                target_service="MSSQL/1433",
                status=finding.status,
                impact=Impact.MEDIUM,
                confidence=finding.confidence,
                summary=finding.summary,
                evidence=finding.evidence,
                blockers=finding.blockers,
                fixes=finding.fixes,
                opsec_notes=finding.opsec_notes,
            )
            path.score = score_path(path)
            paths.append(path)
            index += 1

    if sources:
        concrete = _build_source_paths(findings, sources, max_noise=max_noise, scope=scope)
        blocked = [path for path in paths if path.status == Status.BLOCKED]
        return _finalize_paths(concrete + blocked)

    return _finalize_paths(paths)


def _build_source_paths(
    findings: list[Finding],
    sources: list[SourceAsset],
    max_noise: NoiseLevel | None,
    scope: ScopePolicy | None,
) -> list[RelayPath]:
    paths: list[RelayPath] = []
    index = 1
    for finding in sorted(findings, key=lambda item: (item.host, item.protocol, item.port, item.name)):
        target = _target_descriptor(finding)
        if not target:
            continue
        target_protocol, target_service, status, impact = target
        if scope and not scope.contains(finding.host):
            continue
        for source in sorted(sources, key=lambda item: item.host):
            if scope and not scope.contains(source.host):
                continue
            for capability in compatible_source_capabilities(
                source,
                target_protocol=target_protocol,
                max_noise=max_noise,
            ):
                path = _source_path(index, source, capability, finding, target_service, status, impact)
                path.score = score_path(path)
                paths.append(path)
                index += 1
    return paths


def _target_descriptor(finding: Finding) -> tuple[str, str, Status, Impact] | None:
    if finding.protocol == "smb" and finding.name == "smb_signing":
        if finding.status != Status.RELAYABLE:
            return None
        return "smb", "SMB/445", Status.CANDIDATE, Impact.MEDIUM
    if (
        finding.protocol in {"http", "https"}
        and finding.status in {Status.CANDIDATE, Status.RELAYABLE}
        and finding.name in {"http_ntlm_endpoint", "adcs_web_enrollment", "winrm_http_ntlm"}
    ):
        target_service = f"{finding.protocol.upper()}/{finding.port}"
        if finding.name == "adcs_web_enrollment":
            target_service += " /certsrv"
        elif finding.name == "winrm_http_ntlm":
            target_service += " /wsman"
        return finding.protocol, target_service, Status.CANDIDATE, finding.impact
    if finding.protocol in {"ldap", "ldaps"} and finding.status in {Status.CANDIDATE, Status.RELAYABLE}:
        return finding.protocol, f"{finding.protocol.upper()}/{finding.port}", Status.CANDIDATE, Impact.MEDIUM
    if finding.protocol == "mssql" and finding.status in {Status.CANDIDATE, Status.RELAYABLE}:
        return "mssql", "MSSQL/1433", Status.CANDIDATE, Impact.MEDIUM
    return None


def _source_path(
    index: int,
    source: SourceAsset,
    capability: SourceCapabilitySpec,
    finding: Finding,
    target_service: str,
    status: Status,
    impact: Impact,
) -> RelayPath:
    route = assess_route(
        source,
        finding.host,
        target_protocol=finding.protocol,
        target_port=finding.port,
    )
    path_status = status if route.reachable else Status.BLOCKED
    path_confidence = finding.confidence if route.reachable else Confidence.LOW
    route_blockers = [] if route.reachable else ["Source route profile does not show reachability to the target."]
    opsec = [
        f"Source capability: {capability.label}.",
        f"Route awareness: {route.state} ({route.risk_level} risk).",
        *capability.opsec_notes,
        *source.notes,
        *finding.opsec_notes,
    ]
    if source.routes:
        opsec.append(f"Candidate route metadata: {', '.join(source.routes)}.")
    evidence = [
        Evidence(
            EvidenceType.INFERRED,
            "source_capability",
            capability.key,
            Confidence.MEDIUM,
            raw={
                "source": source.host,
                "label": capability.label,
                "source_protocol": capability.source_protocol,
                "tags": source.tags,
            },
            detail=capability.summary,
        ),
        Evidence(
            EvidenceType.INFERRED,
            "source_noise_level",
            capability.noise.value,
            Confidence.MEDIUM,
            detail="Estimated OPSEC noise for the modeled source capability.",
        ),
    ]
    if source.session:
        evidence.append(
            Evidence(
                EvidenceType.INFERRED,
                "source_session",
                source.session,
                Confidence.MEDIUM,
                detail="Operator-supplied source session or pivot identifier.",
            )
        )
    if source.segment:
        evidence.append(
            Evidence(
                EvidenceType.INFERRED,
                "source_segment",
                source.segment,
                Confidence.MEDIUM,
                detail="Operator-supplied source network segment label.",
            )
        )
    if source.subnets:
        evidence.append(
            Evidence(
                EvidenceType.INFERRED,
                "source_subnets",
                source.subnets,
                Confidence.MEDIUM,
                detail="Operator-supplied source-local subnets for direct reachability modeling.",
            )
        )
    if source.routes:
        evidence.append(
            Evidence(
                EvidenceType.INFERRED,
                "source_routes",
                source.routes,
                Confidence.LOW,
                detail="Operator-supplied route or pivot metadata.",
            )
        )
    evidence.extend(route_evidence(route))
    path = RelayPath(
        id=_path_id(index),
        source=source.host,
        transport=f"{capability.source_protocol} -> {finding.protocol.upper()}",
        target=finding.host,
        target_service=target_service,
        status=path_status,
        impact=_higher_impact(impact, capability.impact_hint),
        confidence=path_confidence,
        summary=(
            f"{capability.label} can theoretically feed {target_service} on {finding.host}. "
            f"Route state: {route.state}. {finding.summary}"
        ),
        evidence=evidence + finding.evidence,
        blockers=[*route_blockers, *capability.blockers, *finding.blockers],
        fixes=[*capability.fixes, *finding.fixes],
        opsec_notes=opsec,
    )
    return path


def _higher_impact(left: Impact, right: Impact) -> Impact:
    order = {
        Impact.INFO: 0,
        Impact.LOW: 1,
        Impact.MEDIUM: 2,
        Impact.HIGH: 3,
        Impact.CRITICAL: 4,
    }
    return left if order[left] >= order[right] else right


def _renumber(paths: list[RelayPath]) -> list[RelayPath]:
    for index, path in enumerate(paths, start=1):
        path.id = _path_id(index)
    return paths


def _finalize_paths(paths: list[RelayPath]) -> list[RelayPath]:
    annotate_paths(paths)
    for path in paths:
        path.score = score_path(path)
    return _renumber(sorted(paths, key=lambda p: p.score, reverse=True))


def remediation_counts(paths: list[RelayPath]) -> list[tuple[str, int, float]]:
    stats: dict[str, tuple[int, float]] = {}
    for path in paths:
        for fix in path.fixes:
            count, score = stats.get(fix, (0, 0.0))
            stats[fix] = (count + 1, score + path.score)
    return sorted(
        [(fix, count, round(score, 2)) for fix, (count, score) in stats.items()],
        key=lambda item: (item[2], item[1], item[0]),
        reverse=True,
    )
