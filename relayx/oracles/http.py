from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..classifiers import classify_http_auth_validation
from ..models import Confidence, Evidence, EvidenceType, Finding, Impact, Status
from .evidence import response_classification_evidence
from ..ntlm import (
    channel_bindings_hash_from_cert_sha256,
    extract_ntlm_challenge,
    make_type1_b64,
    make_type3_b64,
    parse_type2_b64,
    tls_cert_sha256,
)


DEFAULT_PATHS = ["/", "/certsrv/", "/certsrv/certfnsh.asp", "/wsman"]


@dataclass(slots=True)
class HttpProbe:
    scheme: str
    host: str
    port: int
    path: str
    status_code: int
    headers: dict[str, str]
    auth_headers: list[str]
    ntlm_type2: dict | None = None
    tls_cert_sha256: str = ""
    auth_validation: dict | None = None


def _request(
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: float,
    challenge_flow: bool = True,
    auth_validation: bool = False,
) -> HttpProbe:
    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    if scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = conn_cls(host, port=port, timeout=timeout, context=context)
    else:
        conn = conn_cls(host, port=port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "RelayX/0.1", "Connection": "keep-alive"})
        resp = conn.getresponse()
        header_pairs = resp.getheaders()
        headers = _headers_dict(header_pairs)
        auth_headers = _auth_headers_from_pairs(header_pairs)
        cert_hash = ""
        if scheme == "https" and conn.sock:
            cert_hash = tls_cert_sha256(conn.sock.getpeercert(binary_form=True))
        resp.read(512)
        type2 = None
        validation = None
        if challenge_flow and _has_ntlm_auth_values(auth_headers):
            type2, validation = _request_ntlm_type2(
                conn,
                path,
                auth_headers,
                auth_validation=auth_validation,
                tls_cert_hash=cert_hash,
            )
        return HttpProbe(
            scheme,
            host,
            port,
            path,
            resp.status,
            headers,
            auth_headers,
            type2,
            cert_hash,
            validation,
        )
    finally:
        conn.close()


def _headers_dict(pairs: list[tuple[str, str]]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in pairs:
        clean = key.lower()
        if clean in headers:
            headers[clean] = f"{headers[clean]}, {value}"
        else:
            headers[clean] = value
    return headers


def _auth_headers_from_pairs(pairs: list[tuple[str, str]]) -> list[str]:
    return [value for key, value in pairs if key.lower() == "www-authenticate"]


def _request_ntlm_type2(
    conn: http.client.HTTPConnection,
    path: str,
    auth_headers: list[str],
    auth_validation: bool,
    tls_cert_hash: str,
) -> tuple[dict | None, dict | None]:
    if not _has_ntlm_auth_values(auth_headers):
        return None, None
    try:
        conn.request(
            "GET",
            path,
            headers={
                "User-Agent": "RelayX/0.1",
                "Authorization": f"NTLM {make_type1_b64()}",
                "Connection": "keep-alive",
            },
        )
        resp = conn.getresponse()
        type2_headers = _auth_headers_from_pairs(resp.getheaders())
        resp.read(512)
    except (OSError, http.client.HTTPException):
        return None, None
    token = extract_ntlm_challenge(type2_headers)
    if not token:
        return None, None
    try:
        parsed = parse_type2_b64(token)
    except ValueError:
        return None, None
    type2 = {
        "flags": parsed.flags,
        "challenge": parsed.challenge,
        "target_name": parsed.target_name,
        "target_info": parsed.target_info,
        "target_info_raw": parsed.target_info_raw,
        "target_info_hex": parsed.target_info_hex,
    }
    validation = None
    if auth_validation:
        validation = _request_ntlm_type3_validation(conn, path, parsed, tls_cert_hash)
    return type2, validation


def _request_ntlm_type3_validation(
    conn: http.client.HTTPConnection,
    path: str,
    type2,
    tls_cert_hash: str,
) -> dict:
    cbt_hash = None
    cbt_mode = "not_available"
    if tls_cert_hash:
        cbt_hash = channel_bindings_hash_from_cert_sha256(tls_cert_hash)
        cbt_mode = "tls-server-end-point"
    try:
        conn.request(
            "GET",
            path,
            headers={
                "User-Agent": "RelayX/0.1",
                "Authorization": f"NTLM {make_type3_b64(type2, cbt_hash=cbt_hash)}",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        pairs = resp.getheaders()
        body = resp.read(512)
        return {
            "sent": True,
            "synthetic_credentials": True,
            "cbt_mode": cbt_mode,
            "cbt_hash": cbt_hash.hex() if cbt_hash else "",
            "status_code": resp.status,
            "reason": resp.reason,
            "www_authenticate": _headers_dict(pairs).get("www-authenticate", ""),
            "body_sample_hex": body[:64].hex(),
            "interpretation": (
                "Server response to synthetic NTLM Authenticate captured. "
                "This is enforcement evidence, not proof of valid credentials."
            ),
        }
    except (OSError, http.client.HTTPException) as exc:
        return {
            "sent": True,
            "synthetic_credentials": True,
            "cbt_mode": cbt_mode,
            "cbt_hash": cbt_hash.hex() if cbt_hash else "",
            "error": str(exc),
        }


def _auth_headers(headers: dict[str, str]) -> list[str]:
    values = []
    for key, value in headers.items():
        if key == "www-authenticate":
            values.extend([part.strip() for part in value.split(",")])
    return values


def _has_ntlm_auth_values(values: list[str]) -> bool:
    auth = " ".join(values).lower()
    return "ntlm" in auth or "negotiate" in auth


def _has_ntlm(headers: dict[str, str]) -> bool:
    return _has_ntlm_auth_values(_auth_headers(headers))


def _classify_path(path: str) -> tuple[str, Impact, list[str]]:
    clean = path.lower()
    if clean.startswith("/certsrv"):
        return (
            "adcs_web_enrollment",
            Impact.HIGH,
            [
                "Enable Extended Protection for Authentication on AD CS Web Enrollment.",
                "Disable AD CS Web Enrollment if it is not required.",
                "Restrict NTLM on the certificate enrollment web endpoint.",
            ],
        )
    if clean.startswith("/wsman"):
        return (
            "winrm_http_ntlm",
            Impact.MEDIUM,
            [
                "Require HTTPS with Extended Protection for WinRM where applicable.",
                "Restrict NTLM for WinRM endpoints where operationally feasible.",
            ],
        )
    return (
        "http_ntlm_endpoint",
        Impact.MEDIUM,
        [
            "Enable Extended Protection for Authentication on NTLM-enabled IIS endpoints.",
            "Disable NTLM on web applications where Kerberos or modern authentication is possible.",
        ],
    )


def assess_url(
    url: str,
    timeout: float = 4.0,
    challenge_flow: bool = True,
    auth_validation: bool = False,
) -> Finding:
    parsed = urlsplit(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or parsed.path
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path if parsed.hostname else "/"
    if not path:
        path = "/"
    try:
        probe = _request(
            scheme,
            host,
            port,
            path,
            timeout,
            challenge_flow=challenge_flow,
            auth_validation=auth_validation,
        )
    except OSError as exc:
        return Finding(
            host=host,
            port=port,
            protocol=scheme,
            name="http_ntlm",
            status=Status.UNKNOWN,
            confidence=Confidence.LOW,
            summary="HTTP endpoint could not be assessed.",
            evidence=[
                Evidence(EvidenceType.ERROR, "http_probe_error", str(exc), Confidence.LOW)
            ],
            error=str(exc),
        )
    return _finding_from_probe(probe)


def assess(
    host: str,
    port: int,
    scheme: str,
    timeout: float = 4.0,
    paths: list[str] | None = None,
    challenge_flow: bool = True,
    auth_validation: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths or DEFAULT_PATHS:
        try:
            probe = _request(
                scheme,
                host,
                port,
                path,
                timeout,
                challenge_flow=challenge_flow,
                auth_validation=auth_validation,
            )
        except OSError as exc:
            findings.append(
                Finding(
                    host=host,
                    port=port,
                    protocol=scheme,
                    name=f"http_probe:{path}",
                    status=Status.UNKNOWN,
                    confidence=Confidence.LOW,
                    summary=f"{scheme.upper()} {path} could not be assessed.",
                    evidence=[
                        Evidence(EvidenceType.ERROR, "http_probe_error", str(exc), Confidence.LOW)
                    ],
                    error=str(exc),
                )
            )
            continue
        findings.append(_finding_from_probe(probe))
    return findings


def _finding_from_probe(probe: HttpProbe) -> Finding:
    has_ntlm = _has_ntlm(probe.headers)
    endpoint_name, impact, fixes = _classify_path(probe.path)
    auth_header = probe.headers.get("www-authenticate", "")
    type2_observed = probe.ntlm_type2 is not None
    auth_validation_observed = probe.auth_validation is not None
    classification = classify_http_auth_validation(probe.auth_validation)
    if has_ntlm:
        status = Status.CANDIDATE
        confidence = Confidence.HIGH if type2_observed else Confidence.MEDIUM
        summary = f"{probe.scheme.upper()} endpoint advertises NTLM/Negotiate authentication."
        if type2_observed:
            summary += " NTLM Type2 challenge was observed."
        if auth_validation_observed:
            summary += " Synthetic Type3 validation response was captured."
        blockers = ["EPA enforcement not proven without authenticate-message validation"]
        if auth_validation_observed:
            blockers = ["Synthetic credentials were rejected; compare response semantics in an authorized lab before claiming EPA state"]
        opsec = [
            "HTTP GET plus NTLM Type1 challenge-flow when supported; no credentials are submitted.",
        ]
        if auth_validation_observed:
            opsec.append(
                "Explicit auth-validation sent a synthetic NTLM Type3 with random placeholder credentials."
            )
    else:
        status = Status.UNKNOWN if probe.status_code in {401, 403} else Status.BLOCKED
        confidence = Confidence.LOW if probe.status_code in {401, 403} else Confidence.MEDIUM
        summary = f"{probe.scheme.upper()} endpoint did not advertise NTLM in unauthenticated response."
        blockers = ["No NTLM challenge observed"]
        fixes = []
        opsec = ["Single HTTP GET request; no authentication attempted."]

    evidence = [
        Evidence(
            EvidenceType.OBSERVED,
            "http_status",
            probe.status_code,
            Confidence.HIGH,
            raw={"path": probe.path},
        ),
        Evidence(
            EvidenceType.OBSERVED,
            "www_authenticate",
            auth_header,
            Confidence.MEDIUM,
        ),
        Evidence(
            EvidenceType.OBSERVED if type2_observed else EvidenceType.INFERRED,
            "ntlm_type2_challenge",
            bool(type2_observed),
            Confidence.HIGH if type2_observed else Confidence.LOW,
            raw=probe.ntlm_type2 or {},
        ),
        Evidence(
            EvidenceType.OBSERVED if auth_validation_observed else EvidenceType.INFERRED,
            "ntlm_authenticate_validation",
            bool(auth_validation_observed),
            Confidence.MEDIUM if auth_validation_observed else Confidence.LOW,
            raw=probe.auth_validation or {},
            detail="Explicit validation sends synthetic credentials and captures server rejection semantics.",
        ),
        *response_classification_evidence(
            classification=classification,
            observed=auth_validation_observed,
            protocol=probe.scheme,
        ),
        Evidence(
            EvidenceType.INFERRED,
            "epa_status",
            "unknown",
            Confidence.LOW,
            detail="Type2 challenge proves NTLM negotiation, but EPA enforcement requires authenticate-message validation.",
        ),
    ]
    if probe.tls_cert_sha256:
        evidence.append(
            Evidence(
                EvidenceType.OBSERVED,
                "tls_certificate_sha256",
                probe.tls_cert_sha256,
                Confidence.MEDIUM,
                detail="Useful input for future tls-server-end-point CBT validation.",
            )
        )

    return Finding(
        host=probe.host,
        port=probe.port,
        protocol=probe.scheme,
        name=endpoint_name,
        status=status,
        confidence=confidence,
        impact=impact if has_ntlm else Impact.INFO,
        summary=summary,
        evidence=evidence,
        blockers=blockers,
        fixes=fixes,
        opsec_notes=opsec,
    )
