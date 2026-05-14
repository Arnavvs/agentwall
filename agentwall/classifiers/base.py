from __future__ import annotations

from typing import Protocol

from agentwall.core.evidence import DetectionEvidence
from agentwall.core.payload import NormalizedPayload


class Classifier(Protocol):
    async def classify(
        self,
        payload: NormalizedPayload,
        variants: list[NormalizedPayload] | None = None,
    ) -> list[DetectionEvidence]: ...
