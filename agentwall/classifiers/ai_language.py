from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from agentwall.classifiers.base import Classifier
from agentwall.core.evidence import DetectionEvidence
from agentwall.core.payload import NormalizedPayload

SUSPICIOUS_PHRASES = [
    "ignore", "previous", "system prompt", "developer mode",
    "dan", "disregard", "override", "reveal", "repeat",
]


@dataclass
class PIIEntity:
    category: str
    text: str
    confidence: float


class AILanguageClassifier(Classifier):
    def __init__(self, endpoint: str | None = None, api_key: str | None = None) -> None:
        self._endpoint = endpoint or os.environ.get("AGENTWALL_AL_ENDPOINT", "")
        self._api_key = api_key or os.environ.get("AGENTWALL_AL_KEY", "")
        self._available = bool(self._endpoint)

    async def classify(
        self,
        payload: NormalizedPayload,
        variants: list[NormalizedPayload] | None = None,
    ) -> list[DetectionEvidence]:
        evidences: list[DetectionEvidence] = []
        text_lower = payload.text.lower()
        for phrase in SUSPICIOUS_PHRASES:
            if phrase in text_lower:
                evidences.append(
                    DetectionEvidence(
                        detector_id=f"ai_language.suspicious_phrase.{phrase}",
                        vector="prompt_injection",
                        weight=0.20,
                        triggered=True,
                        raw_score=0.5,
                        metadata={"phrase": phrase},
                    )
                )
                break
        return evidences

    async def detect_pii(self, text: str) -> list[PIIEntity]:
        if not self._available:
            return []
        try:
            result = await self._call_pii(text)
            entities = []
            for doc in result.get("documents", []):
                for entity in doc.get("entities", []):
                    if entity.get("confidenceScore", 0) >= 0.85:
                        entities.append(
                            PIIEntity(
                                category=entity.get("category", "Unknown"),
                                text=entity.get("text", ""),
                                confidence=entity.get("confidenceScore", 0),
                            )
                        )
            return entities
        except Exception:
            return []

    async def _call_pii(self, text: str) -> dict[str, Any]:
        url = f"{self._endpoint.rstrip('/')}/text/analytics/v3.2/entities/recognition/pii"
        params = {"api-version": "2023-04-01"}
        body = {"documents": [{"id": "1", "text": text, "language": "en"}]}
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Ocp-Apim-Subscription-Key"] = self._api_key
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, params=params, json=body, headers=headers)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]
