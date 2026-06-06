from __future__ import annotations

import socket
import ssl

from ..classifiers import classify_ldap_auth_validation
from ..ldap_proto import query_root_dse, request_ntlm_challenge
from ..models import Confidence, Evidence, EvidenceType, Finding, Impact, Status
from ..ntlm import tls_cert_sha256
from .evidence import response_classification_evidence


def assess(
    host: str,
    port: int = 389,
    timeout: float = 3.0,
    challenge_flow: bool = True,
    auth_validation: bool = False,
) -> Finding:
    protocol = "ldaps" if port == 636 else "ldap"
    try:
        root_dse, cert_der = query_root_dse(host, port, timeout=timeout)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return Finding(
            host=host,
            port=port,
            protocol=protocol,
            name="ldap_reachability",
            status=Status.UNKNOWN,
            confidence=Confidence.LOW,
            summary=f"{protocol.upper()} could not be reached.",
            evidence=[Evidence(EvidenceType.ERROR, "ldap_probe_error", str(exc), Confidence.LOW)],
            error=str(exc),
        )

    challenge = None
    challenge_error = ""
    if challenge_flow:
        try:
            challenge, cert_der_challenge = request_ntlm_challenge(
                host,
                port,
                timeout=timeout,
                auth_validation=auth_validation,
            )
            cert_der = cert_der or cert_der_challenge
        except (OSError, ssl.SSLError, ValueError) as exc:
            challenge_error = str(exc)

    sasl_mechanisms = root_dse.attributes.get("supportedSASLMechanisms", [])
    ntlm_type2 = challenge.type2 if challenge else None
    type2_observed = ntlm_type2 is not None
    auth_validation_observed = bool(challenge and challenge.auth_validation)
    classification = classify_ldap_auth_validation(
        challenge.auth_validation if challenge and challenge.auth_validation else None
    )
    name = "ldaps_channel_binding" if port == 636 else "ldap_signing"
    confidence = Confidence.MEDIUM if type2_observed else Confidence.LOW
    status = Status.CANDIDATE if type2_observed else Status.UNKNOWN
    summary = f"{protocol.upper()} rootDSE is reachable."
    if type2_observed:
        summary += " SASL NTLM Type2 challenge was observed."
        if auth_validation_observed:
            summary += " Synthetic Type3 validation response was captured."
    elif challenge_error:
        summary += " SASL NTLM challenge-flow failed."
    else:
        summary += " Signing/CBT enforcement requires authenticated validation."
    evidence = [
        Evidence(EvidenceType.OBSERVED, f"{protocol}_reachable", True, Confidence.HIGH),
        Evidence(
            EvidenceType.OBSERVED,
            "rootdse_supported_sasl_mechanisms",
            sasl_mechanisms,
            Confidence.MEDIUM,
        ),
        Evidence(
            EvidenceType.OBSERVED,
            "rootdse_dns_host_name",
            root_dse.attributes.get("dnsHostName", []),
            Confidence.MEDIUM,
        ),
        Evidence(
            EvidenceType.OBSERVED if type2_observed else EvidenceType.INFERRED,
            "ldap_sasl_ntlm_type2_challenge",
            bool(type2_observed),
            Confidence.HIGH if type2_observed else Confidence.LOW,
            raw=ntlm_type2 or {},
        ),
        Evidence(
            EvidenceType.OBSERVED if auth_validation_observed else EvidenceType.INFERRED,
            "ldap_ntlm_authenticate_validation",
            auth_validation_observed,
            Confidence.MEDIUM if auth_validation_observed else Confidence.LOW,
            raw=(challenge.auth_validation if challenge and challenge.auth_validation else {}),
            detail="Explicit validation sends synthetic credentials and captures LDAP bind rejection semantics.",
        ),
        *response_classification_evidence(
            classification=classification,
            observed=auth_validation_observed,
            protocol=protocol,
        ),
    ]
    if cert_der:
        evidence.append(
            Evidence(
                EvidenceType.OBSERVED,
                "tls_certificate_sha256",
                tls_cert_sha256(cert_der),
                Confidence.MEDIUM,
                detail="Useful input for future LDAPS CBT validation.",
            )
        )
    if challenge_error:
        evidence.append(Evidence(EvidenceType.ERROR, "ldap_ntlm_challenge_error", challenge_error, Confidence.LOW))
    if challenge:
        evidence.append(
            Evidence(
                EvidenceType.OBSERVED,
                "ldap_bind_result_code",
                challenge.result_code,
                Confidence.MEDIUM,
                detail=challenge.diagnostic_message,
            )
        )

    blockers = [
        "LDAP signing enforcement not proven without completing authenticated bind validation"
    ]
    if auth_validation_observed:
        blockers = [
            "Synthetic credentials were rejected; compare LDAP result codes in an authorized lab before claiming signing/EPA state"
        ]
    if port == 636:
        blockers.append("LDAPS channel binding enforcement not proven without authenticate-message CBT validation")
    fixes = [
        "Require LDAP signing on domain controllers.",
        "Prefer LDAPS with channel binding enforcement for compatible clients.",
    ]
    if port == 636:
        fixes = [
            "Require LDAP channel binding where compatible.",
            "Audit Event IDs related to LDAP signing and channel binding before enforcement.",
        ]

    return Finding(
        host=host,
        port=port,
        protocol=protocol,
        name=name,
        status=status,
        confidence=confidence,
        impact=Impact.MEDIUM,
        summary=summary,
        evidence=evidence,
        blockers=blockers,
        fixes=fixes,
        opsec_notes=[
            "Anonymous rootDSE query plus optional SASL NTLM Type1 challenge-flow; no credentials are submitted."
        ]
        + (
            ["Explicit auth-validation sent a synthetic NTLM Type3 with random placeholder credentials."]
            if auth_validation_observed
            else []
        ),
    )
