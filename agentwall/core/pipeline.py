from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agentwall.classifiers.base import Classifier
from agentwall.core.action import Action
from agentwall.core.context import get_correlation_id
from agentwall.core.event import ThreatEvent, ThreatScore
from agentwall.core.evidence import DetectionEvidence
from agentwall.core.payload import NormalizedPayload
from agentwall.normalizer import NormalizationResult, Normalizer
from agentwall.policy.engine import PolicyEngine
from agentwall.scoring.scorer import ThreatScorer

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    action: Action
    payload: NormalizedPayload
    threat_score: ThreatScore
    reason: str | None = None
    evidences: list[DetectionEvidence] = field(default_factory=list)


class Pipeline:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        classifiers: list[Classifier],
        scorer: ThreatScorer,
        audit_emitter: Any | None = None,
        normalizer: Normalizer | None = None,
    ) -> None:
        self.policy_engine = policy_engine
        self.classifiers = classifiers
        self.scorer = scorer
        self.audit_emitter = audit_emitter
        self.normalizer = normalizer or Normalizer()

    async def run_inbound(self, payload: NormalizedPayload) -> ActionResult:
        correlation_id = get_correlation_id()
        agent_id = payload.agent_id

        norm_result: NormalizationResult = self.normalizer.normalize(payload)
        canonical = norm_result.canonical
        variants = norm_result.variants

        all_evidences: list[DetectionEvidence] = []
        latencies: dict[str, float] = {}

        import asyncio

        tasks = []
        for c in self.classifiers:
            tasks.append(c.classify(canonical, variants))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("classifier_error: %s", result)
                continue
            if isinstance(result, list):
                all_evidences.extend(result)

        threat_score = self.scorer.score(all_evidences)
        primary_vector = threat_score.primary_vector or "unknown"
        action = self.policy_engine.action_for(agent_id, primary_vector, threat_score.severity)

        if action != Action.ALLOW and self.audit_emitter:
            event = ThreatEvent.from_inbound_result(
                agent_id=agent_id,
                correlation_id=correlation_id,
                vector=primary_vector,
                severity=threat_score.severity,
                action=action,
                threat_score=threat_score.score,
                text=canonical.text,
                evidences=all_evidences,
                latencies=latencies,
            )
            try:
                await self.audit_emitter.emit(event)
            except Exception:
                logger.exception("audit_emit_failed")

        if action != Action.ALLOW:
            reason = f"{threat_score.severity.value} via {primary_vector}"
        else:
            reason = None

        return ActionResult(
            action=action,
            payload=canonical,
            threat_score=threat_score,
            reason=reason,
            evidences=all_evidences,
        )

    async def run_outbound(self, payload: NormalizedPayload) -> ActionResult:
        agent_id = payload.agent_id

        all_evidences: list[DetectionEvidence] = []
        for c in self.classifiers:
            try:
                evidences = await c.classify(payload)
                all_evidences.extend(evidences)
            except Exception:
                logger.exception("outbound_classifier_error")

        threat_score = self.scorer.score(all_evidences)
        primary_vector = threat_score.primary_vector or "outbound"
        action = self.policy_engine.action_for(agent_id, primary_vector, threat_score.severity)

        if action != Action.ALLOW:
            reason = f"{threat_score.severity.value} via {primary_vector}"
        else:
            reason = None

        return ActionResult(
            action=action,
            payload=payload,
            threat_score=threat_score,
            reason=reason,
            evidences=all_evidences,
        )
