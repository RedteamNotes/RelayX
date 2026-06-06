from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


ORACLE_HARDENING_VERSION = "protocol-oracle-v1"


@dataclass(slots=True)
class Classification:
    state: str
    confidence: str
    epa_cbt: str
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    subclassification: str = "not_available"
    policy_inference: str = "not_evaluated"
    oracle_signature: str = ""
    observations: list[str] = field(default_factory=list)
    remaining_uncertainty: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "oracle_version": ORACLE_HARDENING_VERSION,
            "state": self.state,
            "confidence": self.confidence,
            "epa_cbt": self.epa_cbt,
            "subclassification": self.subclassification,
            "policy_inference": self.policy_inference,
            "oracle_signature": self.oracle_signature,
            "observations": self.observations,
            "reasons": self.reasons,
            "limitations": self.limitations,
            "remaining_uncertainty": self.remaining_uncertainty,
        }


def classify_http_auth_validation(validation: dict | None) -> Classification:
    if not validation:
        return _not_performed("HTTP synthetic Type3 validation was not performed.", "http")
    if validation.get("error"):
        signature = _signature("http", "error", _cbt_state(validation))
        return Classification(
            state="inconclusive",
            confidence="low",
            epa_cbt=_cbt_state(validation),
            subclassification="transport_or_protocol_error",
            policy_inference="response_semantics_unavailable",
            oracle_signature=signature,
            observations=_common_observations(validation) + ["transport_error"],
            reasons=[f"HTTP validation failed: {validation['error']}"],
            limitations=["Transport failure prevents response semantics classification."],
            remaining_uncertainty=["Server-side NTLM/EPA behavior was not observable after the Type3 attempt."],
        )

    status_code = _int_value(validation.get("status_code"), default=0)
    text = _combined_text(
        validation.get("reason", ""),
        validation.get("www_authenticate", ""),
        _decode_hex_sample(validation.get("body_sample_hex", "")),
    )
    markers = _semantic_markers(text)
    cbt_hint = _contains_cbt_hint(text)
    cbt_state = _cbt_state(validation)
    if status_code in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
        return Classification(
            state="unexpected_acceptance",
            confidence="high",
            epa_cbt=cbt_state,
            subclassification="synthetic_auth_unexpectedly_accepted",
            policy_inference="unexpected_acceptance",
            oracle_signature=_signature("http", f"status={status_code}", cbt_state, _marker_part(markers)),
            observations=_common_observations(validation) + [f"http_status={status_code}"] + markers,
            reasons=[f"HTTP returned {status_code} after synthetic NTLM Authenticate."],
            limitations=[
                "Synthetic credentials should not be accepted; confirm the endpoint did not ignore authentication."
            ],
            remaining_uncertainty=[
                "Acceptance of synthetic credentials can also indicate mock, proxy, or application-layer behavior."
            ],
        )
    if cbt_hint:
        return Classification(
            state="possible_epa_cbt_enforcement",
            confidence="medium",
            epa_cbt="possible_enforcement_signal",
            subclassification="epa_or_cbt_rejection_signal",
            policy_inference="epa_cbt_enforcement_possible",
            oracle_signature=_signature("http", f"status={status_code}", "epa_cbt_hint", _marker_part(markers)),
            observations=_common_observations(validation) + [f"http_status={status_code}"] + markers,
            reasons=["HTTP response text contains channel-binding or Extended Protection terminology."],
            limitations=["HTTP response wording is not a normative EPA proof; verify in a controlled lab."],
            remaining_uncertainty=[
                "HTTP/IIS wording varies by module and language pack; promote only against calibrated fixtures."
            ],
        )
    if status_code in {401, 403}:
        if cbt_state == "cbt_evidence_available":
            subclassification = "invalid_credentials_with_cbt_no_epa_signal"
            policy_inference = "auth_rejected_with_cbt_material_epa_not_proven"
        else:
            subclassification = "invalid_credentials_no_binding_signal"
            policy_inference = "auth_rejected_epa_not_proven"
        return Classification(
            state="synthetic_auth_rejected",
            confidence="medium",
            epa_cbt=cbt_state,
            subclassification=subclassification,
            policy_inference=policy_inference,
            oracle_signature=_signature("http", f"status={status_code}", cbt_state, _marker_part(markers)),
            observations=_common_observations(validation) + [f"http_status={status_code}"] + markers,
            reasons=[f"HTTP returned {status_code} after synthetic NTLM Authenticate."],
            limitations=[
                "A rejection is expected for random credentials and does not by itself prove EPA/CBT enforcement."
            ],
            remaining_uncertainty=[
                "Random credential rejection cannot distinguish EPA disabled, EPA accepted, and some EPA required states without lab-calibrated response deltas."
            ],
        )
    return Classification(
        state="inconclusive",
        confidence="low",
        epa_cbt=cbt_state,
        subclassification="unmapped_http_response",
        policy_inference="unmapped_response",
        oracle_signature=_signature("http", f"status={status_code}", cbt_state, _marker_part(markers)),
        observations=_common_observations(validation) + [f"http_status={status_code}"] + markers,
        reasons=[f"HTTP returned status {status_code} after synthetic NTLM Authenticate."],
        limitations=["Status code is not mapped to a conservative RelayX interpretation yet."],
        remaining_uncertainty=["The HTTP response did not match RelayX's calibrated semantic families."],
    )


def classify_ldap_auth_validation(validation: dict | None) -> Classification:
    if not validation:
        return _not_performed("LDAP synthetic Type3 validation was not performed.", "ldap")
    if validation.get("error"):
        signature = _signature("ldap", "error", _cbt_state(validation))
        return Classification(
            state="inconclusive",
            confidence="low",
            epa_cbt=_cbt_state(validation),
            subclassification="transport_or_protocol_error",
            policy_inference="response_semantics_unavailable",
            oracle_signature=signature,
            observations=_common_observations(validation) + ["transport_error"],
            reasons=[f"LDAP validation failed: {validation['error']}"],
            limitations=["Bind failure transport details are unavailable."],
            remaining_uncertainty=["LDAP bind response semantics were not available after the Type3 attempt."],
        )

    result_code = _int_value(validation.get("result_code"))
    result_label = str(result_code) if result_code is not None else "unknown"
    diagnostic = str(validation.get("diagnostic_message", ""))
    text = _combined_text(diagnostic)
    markers = _semantic_markers(text)
    cbt_state = _cbt_state(validation)
    if result_code == 0:
        return Classification(
            state="unexpected_acceptance",
            confidence="high",
            epa_cbt=cbt_state,
            subclassification="synthetic_auth_unexpectedly_accepted",
            policy_inference="unexpected_acceptance",
            oracle_signature=_signature("ldap", f"result={result_label}", cbt_state, _marker_part(markers)),
            observations=_common_observations(validation) + [f"ldap_result_code={result_label}"] + markers,
            reasons=["LDAP bind returned success for synthetic NTLM credentials."],
            limitations=[
                "Synthetic credentials should not be accepted; confirm the bind response is not from a mock or proxy."
            ],
            remaining_uncertainty=[
                "Acceptance of synthetic credentials can indicate proxy behavior or a test fixture problem."
            ],
        )
    if "80090346" in text or _contains_cbt_hint(text):
        return Classification(
            state="possible_cbt_enforcement",
            confidence="medium",
            epa_cbt="possible_enforcement_signal",
            subclassification="cbt_binding_rejected",
            policy_inference="cbt_enforcement_possible",
            oracle_signature=_signature("ldap", f"result={result_label}", "cbt_hint", _marker_part(markers)),
            observations=_common_observations(validation) + [f"ldap_result_code={result_label}"] + markers,
            reasons=["LDAP diagnostic text contains CBT-related indicators such as 80090346."],
            limitations=["Active Directory diagnostics vary; validate against known LDAP channel-binding policy states."],
            remaining_uncertainty=[
                "LDAP diagnostic strings vary by DC build, policy state, and localization."
            ],
        )
    if result_code in {8, 13}:
        return Classification(
            state="stronger_auth_or_confidentiality_required",
            confidence="medium",
            epa_cbt=cbt_state,
            subclassification="stronger_auth_or_confidentiality_required",
            policy_inference="stronger_auth_required",
            oracle_signature=_signature("ldap", f"result={result_label}", cbt_state, _marker_part(markers)),
            observations=_common_observations(validation) + [f"ldap_result_code={result_label}"] + markers,
            reasons=[f"LDAP bind returned resultCode {result_code}."],
            limitations=["This indicates a stronger protection requirement but not necessarily CBT enforcement."],
            remaining_uncertainty=[
                "The result code does not uniquely separate LDAP signing, confidentiality, and related policy gates."
            ],
        )
    if result_code == 49:
        if cbt_state == "cbt_evidence_available":
            subclassification = "invalid_credentials_with_cbt_no_cbt_signal"
            policy_inference = "auth_rejected_with_cbt_material_cbt_not_proven"
        else:
            subclassification = "invalid_credentials_no_binding_signal"
            policy_inference = "auth_rejected_cbt_not_proven"
        return Classification(
            state="synthetic_auth_rejected",
            confidence="medium",
            epa_cbt=cbt_state,
            subclassification=subclassification,
            policy_inference=policy_inference,
            oracle_signature=_signature("ldap", f"result={result_label}", cbt_state, _marker_part(markers)),
            observations=_common_observations(validation) + [f"ldap_result_code={result_label}"] + markers,
            reasons=["LDAP returned invalidCredentials for synthetic NTLM Authenticate."],
            limitations=[
                "Invalid credentials are expected and do not by themselves prove signing or channel-binding enforcement."
            ],
            remaining_uncertainty=[
                "Invalid credentials cannot distinguish channel binding never, when-supported, and some always states without calibrated diagnostic deltas."
            ],
        )
    return Classification(
        state="inconclusive",
        confidence="low",
        epa_cbt=cbt_state,
        subclassification="unmapped_ldap_result",
        policy_inference="unmapped_response",
        oracle_signature=_signature("ldap", f"result={result_label}", cbt_state, _marker_part(markers)),
        observations=_common_observations(validation) + [f"ldap_result_code={result_label}"] + markers,
        reasons=[f"LDAP returned resultCode {result_code}."],
        limitations=["Result code is not mapped to a conservative RelayX interpretation yet."],
        remaining_uncertainty=["The LDAP bind result did not match RelayX's calibrated semantic families."],
    )


def classify_mssql_auth_validation(
    validation: dict | None,
    prelogin: dict | None = None,
    tls: dict | None = None,
) -> Classification:
    if not validation:
        if _mssql_tls_not_supported(prelogin):
            return Classification(
                state="not_performed",
                confidence="low",
                epa_cbt="not_evaluated",
                subclassification="tls_or_cbt_unavailable",
                policy_inference="tls_channel_binding_unavailable",
                oracle_signature=_signature("mssql", "auth_validation=not_performed", "encrypt_not_sup"),
                observations=["tds_prelogin_encryption=ENCRYPT_NOT_SUP", "auth_validation_not_performed"],
                reasons=["MSSQL reported ENCRYPT_NOT_SUP; TLS CBT evidence is unavailable."],
                limitations=[
                    "EPA/CBT validation requires a TLS channel or a lab fixture that models the server-side policy."
                ],
                remaining_uncertainty=[
                    "Without TLS, RelayX cannot compute tls-server-end-point CBT material for MSSQL."
                ],
            )
        return _not_performed("MSSQL synthetic Type3 validation was not performed.", "mssql")
    if validation.get("error"):
        signature = _signature("mssql", "error", _cbt_state(validation), _mssql_prelogin_part(prelogin))
        return Classification(
            state="inconclusive",
            confidence="low",
            epa_cbt=_cbt_state(validation),
            subclassification="transport_or_protocol_error",
            policy_inference="response_semantics_unavailable",
            oracle_signature=signature,
            observations=_common_observations(validation)
            + _mssql_context_observations(prelogin, tls)
            + ["transport_error"],
            reasons=[f"MSSQL validation failed: {validation['error']}"],
            limitations=["TDS response semantics are unavailable."],
            remaining_uncertainty=["SQL Server token-stream semantics were not available after the Type3 attempt."],
        )

    errors = [str(item) for item in validation.get("errors", [])]
    infos = [str(item) for item in validation.get("infos", [])]
    text = _combined_text(*errors, *infos)
    markers = _semantic_markers(text)
    cbt_state = _cbt_state(validation)
    observations = (
        _common_observations(validation)
        + _mssql_context_observations(prelogin, tls)
        + [f"mssql_loginack={bool(validation.get('loginack'))}"]
        + markers
    )
    if validation.get("loginack"):
        return Classification(
            state="unexpected_acceptance",
            confidence="high",
            epa_cbt=cbt_state,
            subclassification="synthetic_auth_unexpectedly_accepted",
            policy_inference="unexpected_acceptance",
            oracle_signature=_signature("mssql", "loginack=true", cbt_state, _mssql_prelogin_part(prelogin), _marker_part(markers)),
            observations=observations,
            reasons=["SQL Server returned LOGINACK after synthetic NTLM Authenticate."],
            limitations=["Synthetic credentials should not be accepted; confirm server/proxy behavior."],
            remaining_uncertainty=[
                "LOGINACK for synthetic credentials can indicate proxy behavior, mock fixtures, or an unsafe test account."
            ],
        )
    if "80090346" in text or _contains_cbt_hint(text):
        return Classification(
            state="possible_epa_cbt_enforcement",
            confidence="medium",
            epa_cbt="possible_enforcement_signal",
            subclassification="epa_cbt_binding_rejected",
            policy_inference="epa_cbt_enforcement_possible",
            oracle_signature=_signature("mssql", "loginack=false", "epa_cbt_hint", _mssql_prelogin_part(prelogin), _marker_part(markers)),
            observations=observations,
            reasons=["MSSQL error text contains CBT/EPA-related indicators such as 80090346."],
            limitations=["SQL Server error wording must be calibrated against EPA policy modes in a lab."],
            remaining_uncertainty=[
                "SQL Server error wording depends on encryption mode, driver behavior, and server build."
            ],
        )
    if _contains_login_failure(text) or errors:
        if cbt_state == "cbt_evidence_available":
            subclassification = "invalid_credentials_with_cbt_no_epa_signal"
            policy_inference = "auth_rejected_with_cbt_material_epa_not_proven"
        else:
            subclassification = "invalid_credentials_no_binding_signal"
            policy_inference = "auth_rejected_epa_not_proven"
        return Classification(
            state="synthetic_auth_rejected",
            confidence="medium",
            epa_cbt=cbt_state,
            subclassification=subclassification,
            policy_inference=policy_inference,
            oracle_signature=_signature("mssql", "loginack=false", cbt_state, _mssql_prelogin_part(prelogin), _marker_part(markers)),
            observations=observations,
            reasons=["SQL Server rejected synthetic NTLM Authenticate."],
            limitations=[
                "Credential rejection is expected for random credentials and is not alone proof of EPA enforcement."
            ],
            remaining_uncertainty=[
                "Login failure cannot distinguish EPA disabled, EPA accepted, and some EPA required states without calibrated SQL Server error deltas."
            ],
        )
    return Classification(
        state="inconclusive",
        confidence="low",
        epa_cbt=cbt_state,
        subclassification="unmapped_mssql_token_stream",
        policy_inference="unmapped_response",
        oracle_signature=_signature("mssql", "loginack=false", cbt_state, _mssql_prelogin_part(prelogin), _marker_part(markers)),
        observations=observations,
        reasons=["MSSQL returned no mapped LOGINACK or error semantics."],
        limitations=["TDS token stream requires real-lab calibration."],
        remaining_uncertainty=["The SQL Server token stream did not match RelayX's calibrated semantic families."],
    )


def _not_performed(reason: str, protocol: str = "generic") -> Classification:
    return Classification(
        state="not_performed",
        confidence="low",
        epa_cbt="not_evaluated",
        subclassification="auth_validation_not_performed",
        policy_inference="not_evaluated",
        oracle_signature=_signature(protocol, "auth_validation=not_performed"),
        observations=["auth_validation_not_performed"],
        reasons=[reason],
        limitations=["Run with --auth-validation to capture synthetic Type3 rejection semantics."],
        remaining_uncertainty=["Authenticate-response semantics were not collected."],
    )


def _cbt_state(validation: dict) -> str:
    if validation.get("cbt_hash"):
        return "cbt_evidence_available"
    return "cbt_not_available"


def _combined_text(*values: str) -> str:
    return " ".join(value for value in values if value).lower()


def _decode_hex_sample(value: str) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value).decode("utf-8", "replace")
    except ValueError:
        return ""


def _contains_cbt_hint(text: str) -> bool:
    terms = [
        "channel binding",
        "channel-binding",
        "extended protection",
        "80090346",
        "sec_e_bad_bindings",
        "message altered",
    ]
    return any(term in text for term in terms) or bool(re.search(r"\b(?:epa|cbt)\b", text))


def _contains_login_failure(text: str) -> bool:
    terms = ["login failed", "invalid credentials", "logon failure", "authentication failed"]
    return any(term in text for term in terms)


def _semantic_markers(text: str) -> list[str]:
    markers: list[str] = []
    checks = [
        ("sec_e_bad_bindings", "sec_e_bad_bindings"),
        ("80090346", "80090346"),
        ("message altered", "message_altered"),
        ("channel binding", "channel_binding_term"),
        ("channel-binding", "channel_binding_term"),
        ("extended protection", "extended_protection_term"),
        ("login failed", "login_failed"),
        ("invalid credentials", "invalid_credentials"),
        ("logon failure", "logon_failure"),
        ("authentication failed", "authentication_failed"),
    ]
    for needle, marker in checks:
        if needle in text and marker not in markers:
            markers.append(marker)
    if re.search(r"\bepa\b", text) and "epa_term" not in markers:
        markers.append("epa_term")
    if re.search(r"\bcbt\b", text) and "cbt_term" not in markers:
        markers.append("cbt_term")
    return markers


def _common_observations(validation: dict) -> list[str]:
    observations: list[str] = []
    if validation.get("sent"):
        observations.append("synthetic_type3_sent")
    if validation.get("synthetic_credentials"):
        observations.append("synthetic_credentials_used")
    cbt_mode = str(validation.get("cbt_mode") or "not_available")
    observations.append(f"cbt_mode={_clean_part(cbt_mode)}")
    observations.append(
        "cbt_hash_available" if validation.get("cbt_hash") else "cbt_hash_missing"
    )
    return observations


def _mssql_context_observations(prelogin: dict | None, tls: dict | None) -> list[str]:
    observations: list[str] = []
    if prelogin:
        observations.append(f"tds_prelogin_encryption={_mssql_prelogin_part(prelogin).split('=', 1)[-1]}")
    if tls:
        observations.append("tds_wrapped_tls=true")
        if tls.get("certificate_sha256"):
            observations.append("tls_certificate_sha256_available")
    elif prelogin:
        observations.append("tds_wrapped_tls=false")
    return observations


def _mssql_tls_not_supported(prelogin: dict | None) -> bool:
    if not prelogin:
        return False
    return prelogin.get("encryption") == 2 or str(prelogin.get("encryption_name", "")).upper() == "ENCRYPT_NOT_SUP"


def _mssql_prelogin_part(prelogin: dict | None) -> str:
    if not prelogin:
        return "encrypt=unknown"
    value = str(prelogin.get("encryption_name") or prelogin.get("encryption") or "unknown")
    return f"encrypt={_clean_part(value)}"


def _marker_part(markers: list[str]) -> str:
    return "markers=" + ("+".join(sorted(markers)) if markers else "none")


def _signature(protocol: str, *parts: str) -> str:
    clean_parts = [_clean_part(part) for part in parts if part]
    return ":".join([_clean_part(protocol), *clean_parts])


def _clean_part(value: Any) -> str:
    text = str(value).strip().lower()
    text = re.sub(r"[^a-z0-9_.=+-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "none"


def _int_value(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
