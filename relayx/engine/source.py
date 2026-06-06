from __future__ import annotations

from dataclasses import dataclass

from ..models import Impact, NoiseLevel, SourceAsset


NOISE_RANK = {
    NoiseLevel.PASSIVE: 0,
    NoiseLevel.LOW: 1,
    NoiseLevel.MEDIUM: 2,
    NoiseLevel.HIGH: 3,
}


@dataclass(frozen=True, slots=True)
class SourceCapabilitySpec:
    key: str
    label: str
    source_protocol: str
    compatible_target_protocols: set[str]
    impact_hint: Impact
    noise: NoiseLevel
    summary: str
    opsec_notes: tuple[str, ...]
    blockers: tuple[str, ...] = ()
    fixes: tuple[str, ...] = ()


CAPABILITY_SPECS: dict[str, SourceCapabilitySpec] = {
    "webclient": SourceCapabilitySpec(
        key="webclient",
        label="WebClient/WebDAV NTLM source",
        source_protocol="HTTP/WebDAV",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps", "mssql"},
        impact_hint=Impact.MEDIUM,
        noise=NoiseLevel.MEDIUM,
        summary="Source is modeled as able to emit HTTP/WebDAV NTLM authentication.",
        opsec_notes=(
            "Requires a scoped operator-controlled trigger; RelayX does not trigger WebClient.",
            "Often creates client-side WebClient and outbound HTTP telemetry.",
        ),
        fixes=(
            "Disable WebClient where it is not operationally required.",
            "Restrict outbound WebDAV/HTTP authentication from workstation segments.",
        ),
    ),
    "spooler": SourceCapabilitySpec(
        key="spooler",
        label="Spooler RPC coercion source",
        source_protocol="SMB/RPC",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps", "mssql"},
        impact_hint=Impact.HIGH,
        noise=NoiseLevel.HIGH,
        summary="Source is modeled as having Print Spooler coercion exposure.",
        opsec_notes=(
            "Active coercion is high-noise and should be single-shot and explicitly authorized.",
            "RelayX models readiness only and does not invoke spooler coercion.",
        ),
        blockers=("Confirm spooler service exposure and network reachability before any active validation.",),
        fixes=(
            "Disable Print Spooler on systems that do not require printing.",
            "Restrict RPC access to Print Spooler from untrusted segments.",
        ),
    ),
    "efsrpc": SourceCapabilitySpec(
        key="efsrpc",
        label="EFSRPC coercion source",
        source_protocol="SMB/RPC",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps", "mssql"},
        impact_hint=Impact.HIGH,
        noise=NoiseLevel.HIGH,
        summary="Source is modeled as having EFSRPC-style outbound NTLM coercion exposure.",
        opsec_notes=(
            "Active EFSRPC validation is high-noise and can leave RPC and authentication telemetry.",
            "RelayX records the possibility but does not issue RPC coercion calls.",
        ),
        blockers=("Confirm named-pipe exposure and patch/policy state in an authorized lab.",),
        fixes=("Restrict EFSRPC abuse paths and monitor outbound NTLM from sensitive hosts.",),
    ),
    "dfsnm": SourceCapabilitySpec(
        key="dfsnm",
        label="DFSNM coercion source",
        source_protocol="SMB/RPC",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps", "mssql"},
        impact_hint=Impact.HIGH,
        noise=NoiseLevel.HIGH,
        summary="Source is modeled as having DFSNM-style outbound NTLM coercion exposure.",
        opsec_notes=(
            "Active DFSNM validation should be constrained to one source and one expected callback.",
            "RelayX models the path without invoking DFSNM.",
        ),
        blockers=("Confirm DFS Namespace service exposure before active validation.",),
        fixes=("Restrict DFS management RPC access and monitor unexpected outbound NTLM.",),
    ),
    "fsrvp": SourceCapabilitySpec(
        key="fsrvp",
        label="FSRVP coercion source",
        source_protocol="SMB/RPC",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps", "mssql"},
        impact_hint=Impact.HIGH,
        noise=NoiseLevel.HIGH,
        summary="Source is modeled as having FSRVP-style outbound NTLM coercion exposure.",
        opsec_notes=(
            "Active FSRVP validation can be conspicuous on file servers and backup workflows.",
            "RelayX models readiness only.",
        ),
        blockers=("Confirm File Server VSS Agent exposure and operational impact before testing.",),
        fixes=("Restrict FSRVP/RPC access and monitor unexpected shadow-copy RPC activity.",),
    ),
    "mssql_outbound": SourceCapabilitySpec(
        key="mssql_outbound",
        label="MSSQL outbound NTLM source",
        source_protocol="MSSQL",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps"},
        impact_hint=Impact.HIGH,
        noise=NoiseLevel.HIGH,
        summary="Source SQL Server is modeled as able to emit outbound NTLM through file or network access primitives.",
        opsec_notes=(
            "Active MSSQL outbound validation can create SQL audit, failed access, and outbound auth telemetry.",
            "RelayX models the source capability without invoking SQL procedures.",
        ),
        blockers=("Confirm SQL privileges and outbound egress path before any active validation.",),
        fixes=(
            "Constrain SQL Server service accounts.",
            "Restrict outbound SMB/HTTP from SQL Server segments.",
        ),
    ),
    "name_resolution": SourceCapabilitySpec(
        key="name_resolution",
        label="Name-resolution inducement source",
        source_protocol="LLMNR/NBNS/ADIDNS/SPN",
        compatible_target_protocols={"smb", "http", "https", "ldap", "ldaps", "mssql"},
        impact_hint=Impact.HIGH,
        noise=NoiseLevel.MEDIUM,
        summary="Source segment is modeled as susceptible to name-resolution or naming-control induced NTLM.",
        opsec_notes=(
            "Prefer passive observation or pre-approved naming changes over broad poisoning.",
            "ADIDNS or SPN changes should be scoped, timestamped, and reversible.",
        ),
        blockers=("Confirm naming control, rollback plan, and affected broadcast/domain scope.",),
        fixes=(
            "Disable LLMNR/NBNS where possible.",
            "Harden ADIDNS/SPN write paths and monitor suspicious name registrations.",
        ),
    ),
}


ALIASES = {
    "webdav": "webclient",
    "adidns": "name_resolution",
    "ghost_spn": "name_resolution",
}


def source_capabilities(source: SourceAsset, max_noise: NoiseLevel | None = None) -> list[SourceCapabilitySpec]:
    limit = max_noise or source.noise_limit
    specs: list[SourceCapabilitySpec] = []
    for key, enabled in sorted(source.capabilities.items()):
        if not enabled:
            continue
        normalized = ALIASES.get(key, key)
        spec = CAPABILITY_SPECS.get(normalized)
        if not spec or spec in specs:
            continue
        if noise_allows(spec.noise, source.noise_limit) and noise_allows(spec.noise, limit):
            specs.append(spec)
    return specs


def compatible_source_capabilities(
    source: SourceAsset,
    target_protocol: str,
    max_noise: NoiseLevel | None = None,
) -> list[SourceCapabilitySpec]:
    return [
        spec
        for spec in source_capabilities(source, max_noise=max_noise)
        if target_protocol in spec.compatible_target_protocols
    ]


def noise_allows(value: NoiseLevel, limit: NoiseLevel) -> bool:
    return NOISE_RANK[value] <= NOISE_RANK[limit]
