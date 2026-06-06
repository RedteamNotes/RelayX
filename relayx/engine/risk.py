from __future__ import annotations

from ..models import Confidence, Impact, NoiseLevel, RelayPath, Status
from .source import NOISE_RANK


IMPACT_WEIGHT = {
    Impact.INFO: 0,
    Impact.LOW: 10,
    Impact.MEDIUM: 30,
    Impact.HIGH: 70,
    Impact.CRITICAL: 100,
}

CONFIDENCE_WEIGHT = {
    Confidence.UNKNOWN: 0.4,
    Confidence.LOW: 0.55,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}

STATUS_WEIGHT = {
    Status.RELAYABLE: 1.0,
    Status.CANDIDATE: 0.75,
    Status.UNKNOWN: 0.35,
    Status.BLOCKED: 0.05,
    Status.ERROR: 0.0,
}


def estimate_noise(path: RelayPath) -> NoiseLevel:
    observed = []
    for evidence in path.evidence:
        if evidence.key in {"source_noise_level", "route_noise_level"}:
            try:
                observed.append(NoiseLevel(evidence.value))
            except ValueError:
                continue
    if observed:
        return max(observed, key=lambda item: NOISE_RANK[item])
    text = " ".join([path.transport, path.target_service, *path.opsec_notes]).lower()
    if "coercion" in text or "active" in text:
        return NoiseLevel.HIGH
    if "authentication" in text or "ntlm" in text:
        return NoiseLevel.MEDIUM
    if "single" in text or "connect" in text:
        return NoiseLevel.LOW
    return NoiseLevel.LOW


def score_path(path: RelayPath) -> float:
    base = IMPACT_WEIGHT[path.impact]
    score = base * CONFIDENCE_WEIGHT[path.confidence] * STATUS_WEIGHT[path.status]
    blocker_penalty = min(len(path.blockers) * 5, 25)
    noise_penalty = {
        NoiseLevel.PASSIVE: 0,
        NoiseLevel.LOW: 0,
        NoiseLevel.MEDIUM: 5,
        NoiseLevel.HIGH: 15,
    }[estimate_noise(path)]
    route_penalty = _route_penalty(path)
    return max(0.0, round(score - blocker_penalty - noise_penalty - route_penalty, 2))


def _route_penalty(path: RelayPath) -> float:
    risk_score = 0.0
    reachable = True
    state = ""
    for evidence in path.evidence:
        if evidence.key == "route_risk_score":
            try:
                risk_score = float(evidence.value)
            except (TypeError, ValueError):
                risk_score = 0.0
        elif evidence.key == "route_reachable":
            reachable = bool(evidence.value)
        elif evidence.key == "route_reachability_state":
            state = str(evidence.value)
    penalty = min(risk_score / 5.0, 22.0)
    if state in {"metadata_only", "assumed_reachable"}:
        penalty += 4.0
    if not reachable:
        penalty += 12.0
    return round(penalty, 2)
