from __future__ import annotations

from ..classifiers import classify_mssql_auth_validation
from ..mssql_tds import ntlm_sspi_challenge
from ..models import Confidence, Evidence, EvidenceType, Finding, Impact, Status
from .evidence import response_classification_evidence


MSSQL_PORT = 1433


def assess(
    host: str,
    port: int = MSSQL_PORT,
    timeout: float = 3.0,
    prefer_tls: bool = True,
    auth_validation: bool = False,
) -> Finding:
    try:
        challenge_result = ntlm_sspi_challenge(
            host,
            port=port,
            timeout=timeout,
            prefer_tls=prefer_tls,
            auth_validation=auth_validation,
        )
    except OSError as exc:
        return Finding(
            host=host,
            port=port,
            protocol="mssql",
            name="mssql_reachability",
            status=Status.UNKNOWN,
            confidence=Confidence.LOW,
            summary="MSSQL could not be reached.",
            evidence=[Evidence(EvidenceType.ERROR, "mssql_probe_error", str(exc), Confidence.LOW)],
            error=str(exc),
        )

    prelogin_result = challenge_result.prelogin
    encryption_name = prelogin_result.get("encryption_name", "unknown")
    type2_observed = challenge_result.type2 is not None
    tls_observed = challenge_result.tls is not None
    auth_validation_observed = challenge_result.auth_validation is not None
    classification = classify_mssql_auth_validation(
        challenge_result.auth_validation,
        prelogin=prelogin_result,
        tls=challenge_result.tls,
    )
    if type2_observed:
        status = Status.CANDIDATE
        confidence = Confidence.HIGH
        summary = "MSSQL Login7 integrated-security SSPI Type2 challenge was observed."
        blockers = ["MSSQL EPA/CBT enforcement not proven without authenticate-message validation"]
        if tls_observed:
            summary += " TDS-wrapped TLS completed and CBT evidence was captured."
        if auth_validation_observed:
            summary += " Synthetic Type3 validation response was captured."
    else:
        status = Status.UNKNOWN
        confidence = Confidence.LOW
        summary = "MSSQL prelogin completed, but SSPI Type2 challenge was not observed."
        blockers = ["MSSQL SSPI Type2 challenge not observed"]
        if challenge_result.skipped_reason:
            blockers.append(challenge_result.skipped_reason)

    return Finding(
        host=host,
        port=port,
        protocol="mssql",
        name="mssql_ntlm_epa",
        status=status,
        confidence=confidence,
        impact=Impact.MEDIUM,
        summary=summary,
        evidence=[
            Evidence(EvidenceType.OBSERVED, "mssql_port_open", True, Confidence.HIGH),
            Evidence(
                EvidenceType.OBSERVED,
                "tds_prelogin_encryption",
                encryption_name,
                Confidence.MEDIUM,
                raw=prelogin_result,
            ),
            Evidence(
                EvidenceType.OBSERVED if tls_observed else EvidenceType.INFERRED,
                "tds_wrapped_tls",
                bool(tls_observed),
                Confidence.HIGH if tls_observed else Confidence.LOW,
                raw=challenge_result.tls or {},
            ),
            Evidence(
                EvidenceType.OBSERVED if tls_observed else EvidenceType.INFERRED,
                "mssql_cbt_tls_server_end_point",
                (challenge_result.tls or {}).get("cbt_hash", ""),
                Confidence.HIGH if tls_observed else Confidence.LOW,
                detail=(
                    "CBT evidence is the TLS server certificate hash used for "
                    "tls-server-end-point channel binding."
                ),
            ),
            Evidence(
                EvidenceType.OBSERVED if type2_observed else EvidenceType.INFERRED,
                "mssql_sspi_ntlm_type2_challenge",
                bool(type2_observed),
                Confidence.HIGH if type2_observed else Confidence.LOW,
                raw=challenge_result.type2 or {},
            ),
            Evidence(
                EvidenceType.OBSERVED if auth_validation_observed else EvidenceType.INFERRED,
                "mssql_ntlm_authenticate_validation",
                bool(auth_validation_observed),
                Confidence.MEDIUM if auth_validation_observed else Confidence.LOW,
                raw=challenge_result.auth_validation or {},
                detail="Explicit validation sends synthetic credentials and captures SQL Server rejection semantics.",
            ),
            *response_classification_evidence(
                classification=classification,
                observed=auth_validation_observed,
                protocol="mssql",
            ),
            Evidence(
                EvidenceType.OBSERVED,
                "tds_loginack_observed",
                challenge_result.loginack,
                Confidence.LOW,
            ),
            Evidence(
                EvidenceType.OBSERVED,
                "tds_errors",
                challenge_result.errors,
                Confidence.MEDIUM,
            ),
            Evidence(
                EvidenceType.INFERRED,
                "mssql_epa_enforcement",
                "unknown",
                Confidence.LOW,
                detail=(
                    "Type2 proves SSPI negotiation when present, but EPA/CBT enforcement "
                    "requires authenticate-message validation and TLS channel-binding support."
                ),
            ),
        ],
        blockers=blockers,
        fixes=[
            "Enable Extended Protection for Authentication for SQL Server where supported.",
            "Constrain SQL Server service accounts and outbound authentication exposure.",
        ],
        opsec_notes=[
            "TDS prelogin plus Login7 integrated-security Type1 challenge-flow; no credentials are submitted.",
            "When available, TDS-wrapped TLS is used to collect tls-server-end-point CBT evidence.",
        ],
    )
