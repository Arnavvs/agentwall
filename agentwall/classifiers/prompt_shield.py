from __future__ import annotations

import os
import time
from typing import Any

import httpx

from agentwall.classifiers.base import Classifier
from agentwall.core.evidence import DetectionEvidence
from agentwall.core.payload import NormalizedPayload


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_seconds: int = 30) -> None:
        self._failure_threshold = failure_threshold
        self._recovery_seconds = recovery_seconds
        self._failures = 0
        self._last_failure_time: float = 0
        self._open = False

    def record_failure(self) -> None:
        self._failures += 1
        self._last_failure_time = time.monotonic()
        if self._failures >= self._failure_threshold:
            self._open = True

    def record_success(self) -> None:
        self._failures = 0
        self._open = False

    def is_open(self) -> bool:
        if not self._open:
            return False
        if time.monotonic() - self._last_failure_time > self._recovery_seconds:
            self._open = False
            self._failures = 0
            return False
        return True


class PromptShieldClassifier(Classifier):
    def __init__(self, endpoint: str | None = None, api_key: str | None = None) -> None:
        self._endpoint = endpoint or os.environ.get("AGENTWALL_CS_ENDPOINT", "")
        self._api_key = api_key or os.environ.get("AGENTWALL_CS_KEY", "")
        self._circuit_breaker = CircuitBreaker()
        self._available = bool(self._endpoint)

    async def classify(
        self,
        payload: NormalizedPayload,
        variants: list[NormalizedPayload] | None = None,
    ) -> list[DetectionEvidence]:
        if not self._available or self._circuit_breaker.is_open():
            return []

        try:
            result = await self._call_shield_prompt(payload.text)
        except Exception:
            self._circuit_breaker.record_failure()
            return []

        self._circuit_breaker.record_success()
        evidences: list[DetectionEvidence] = []

        if result.get("userPromptAnalysis", {}).get("attackDetected"):
            evidences.append(
                DetectionEvidence(
                    detector_id="prompt_shield.user_prompt",
                    vector="prompt_injection",
                    weight=0.55,
                    triggered=True,
                    metadata={"source": "prompt_shield"},
                )
            )

        for i, doc_result in enumerate(result.get("documentsAnalysis", [])):
            if doc_result.get("attackDetected"):
                evidences.append(
                    DetectionEvidence(
                        detector_id=f"prompt_shield.documents.{i}",
                        vector="indirect_injection",
                        weight=0.55,
                        triggered=True,
                        metadata={"source": "prompt_shield", "document_index": i},
                    )
                )

        return evidences

    async def _call_shield_prompt(
        self,
        user_prompt: str,
        documents: list[str] | None = None,
    ) -> dict[str, Any]:
        url = f"{self._endpoint.rstrip('/')}/contentsafety/text:shieldPrompt"
        params = {"api-version": "2024-09-01"}
        body: dict[str, Any] = {"userPrompt": user_prompt}
        if documents:
            body["documents"] = documents

        headers: dict[str, str] = {}
        if self._api_key:
            headers["Ocp-Apim-Subscription-Key"] = self._api_key

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, params=params, json=body, headers=headers)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]
