from __future__ import annotations

import math

from agentwall.core.event import ThreatScore
from agentwall.core.evidence import DetectionEvidence
from agentwall.core.severity import Severity

DEFAULT_WEIGHTS: dict[str, float] = {
    "prompt_shield.user_prompt": 0.55,
    "prompt_shield.documents": 0.55,
    "ai_language": 0.30,
    "rule_engine": 0.40,
    "rule_engine.fuzzy": 0.25,
    "mcp_scanner": 0.70,
    "output.secret.regex": 0.85,
    "output.secret.entropy": 0.30,
    "output.system_prompt_leak": 0.75,
    "tool_scope": 1.00,
}

SEVERITY_THRESHOLDS = [
    (0.85, Severity.CRITICAL),
    (0.65, Severity.HIGH),
    (0.40, Severity.MEDIUM),
    (0.15, Severity.LOW),
]


class ThreatScorer:
    def __init__(self, weight_overrides: dict[str, float] | None = None) -> None:
        self._weights = {**DEFAULT_WEIGHTS}
        if weight_overrides:
            self._weights.update(weight_overrides)

    def score(self, evidences: list[DetectionEvidence]) -> ThreatScore:
        if not evidences:
            return ThreatScore(
                severity=Severity.SAFE,
                score=0.0,
                primary_vector=None,
                vector_scores={},
                evidences=[],
            )

        by_vector: dict[str, list[float]] = {}
        for e in evidences:
            if not e.triggered:
                continue
            weight = self._weights.get(e.detector_id, e.weight)
            effective = weight * e.raw_score
            by_vector.setdefault(e.vector, []).append(effective)

        vector_scores: dict[str, float] = {}
        for vector, weights in by_vector.items():
            product = math.prod(1.0 - w for w in weights)
            vector_scores[vector] = max(0.0, min(1.0, 1.0 - product))

        if not vector_scores:
            return ThreatScore(
                severity=Severity.SAFE,
                score=0.0,
                primary_vector=None,
                vector_scores={},
                evidences=evidences,
            )

        max_score = max(vector_scores.values())
        primary_vector = max(vector_scores, key=lambda k: vector_scores[k])

        severity = Severity.SAFE
        for threshold, sev in SEVERITY_THRESHOLDS:
            if max_score >= threshold:
                severity = sev
                break

        return ThreatScore(
            severity=severity,
            score=max_score,
            primary_vector=primary_vector,
            vector_scores=vector_scores,
            evidences=evidences,
        )
