from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentwall.core.action import Action
from agentwall.core.evidence import DetectionEvidence
from agentwall.core.severity import Severity


class ThreatScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    severity: Severity
    score: float
    primary_vector: str | None = None
    vector_scores: dict[str, float] = Field(default_factory=dict)
    evidences: list[DetectionEvidence] = Field(default_factory=list)


class ThreatEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    agent_id: str
    correlation_id: str
    vector: str
    severity: Severity
    action: Action
    detector_evidences: list[DetectionEvidence] = Field(default_factory=list)
    payload_hash: str
    payload_preview: str | None = None
    threat_score: float
    classifier_latencies_ms: dict[str, float] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_inbound_result(
        cls,
        agent_id: str,
        correlation_id: str,
        vector: str,
        severity: Severity,
        action: Action,
        threat_score: float,
        text: str,
        evidences: list[DetectionEvidence] | None = None,
        latencies: dict[str, float] | None = None,
        metadata: dict[str, Any] | None = None,
        include_preview: bool = False,
    ) -> ThreatEvent:
        payload_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
        payload_preview = text[:200] if include_preview else None
        return cls(
            agent_id=agent_id,
            correlation_id=correlation_id,
            vector=vector,
            severity=severity,
            action=action,
            threat_score=threat_score,
            payload_hash=payload_hash,
            payload_preview=payload_preview,
            detector_evidences=evidences or [],
            classifier_latencies_ms=latencies or {},
            metadata=metadata or {},
        )
