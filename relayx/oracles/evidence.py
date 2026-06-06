from __future__ import annotations

from ..classifiers import Classification, ORACLE_HARDENING_VERSION
from ..models import Confidence, Evidence, EvidenceType


def response_classification_evidence(
    *,
    classification: Classification,
    observed: bool,
    protocol: str,
) -> list[Evidence]:
    evidence_type = EvidenceType.OBSERVED if observed else EvidenceType.INFERRED
    confidence = Confidence(classification.confidence)
    raw = classification.as_dict()
    raw["protocol"] = protocol

    return [
        Evidence(
            evidence_type,
            "relayx_response_classification",
            classification.state,
            confidence,
            raw=raw,
            detail=f"Conservative RelayX {protocol.upper()} authenticate-response classification.",
        ),
        Evidence(
            evidence_type,
            "relayx_response_subclassification",
            classification.subclassification,
            confidence,
            raw=raw,
            detail="Finer protocol-oracle state used to explain why a coarse classification can or cannot be promoted.",
        ),
        Evidence(
            evidence_type,
            "relayx_policy_inference",
            classification.policy_inference,
            confidence,
            raw={
                "oracle_version": ORACLE_HARDENING_VERSION,
                "protocol": protocol,
                "classification": classification.state,
                "subclassification": classification.subclassification,
                "remaining_uncertainty": classification.remaining_uncertainty,
            },
            detail="Policy-state inference derived from response semantics and available binding evidence.",
        ),
        Evidence(
            evidence_type,
            "relayx_oracle_signature",
            classification.oracle_signature,
            confidence,
            raw={
                "oracle_version": ORACLE_HARDENING_VERSION,
                "protocol": protocol,
                "classification": classification.state,
                "subclassification": classification.subclassification,
            },
            detail="Stable, sanitized signature for lab calibration and multi-scan comparison.",
        ),
        Evidence(
            evidence_type,
            "relayx_oracle_observations",
            classification.observations,
            confidence,
            raw={"oracle_version": ORACLE_HARDENING_VERSION, "protocol": protocol},
            detail="Normalized protocol observations that avoid embedding raw credentials or target-specific error text.",
        ),
        Evidence(
            evidence_type,
            "relayx_remaining_uncertainty",
            classification.remaining_uncertainty,
            confidence,
            raw={"oracle_version": ORACLE_HARDENING_VERSION, "protocol": protocol},
            detail="Reasons the oracle remains conservative without matching lab calibration.",
        ),
    ]
