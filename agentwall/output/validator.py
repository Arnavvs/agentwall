from __future__ import annotations

from agentwall.core.evidence import DetectionEvidence
from agentwall.core.payload import NormalizedPayload
from agentwall.output.secrets import SecretScanner
from agentwall.output.system_prompt_leak import SystemPromptLeakDetector


class OutputValidator:
    def __init__(
        self,
        system_prompt: str = "",
        leak_threshold: int = 80,
    ) -> None:
        self._secret_scanner = SecretScanner()
        self._leak_detector = (
            SystemPromptLeakDetector(system_prompt, leak_threshold)
            if system_prompt
            else None
        )

    async def validate(self, payload: NormalizedPayload) -> list[DetectionEvidence]:
        evidences: list[DetectionEvidence] = []
        text = payload.text

        if self._leak_detector and self._leak_detector.check(text):
            evidences.append(
                DetectionEvidence(
                    detector_id="output.system_prompt_leak",
                    vector="prompt_leaking",
                    weight=0.75,
                    triggered=True,
                )
            )

        secrets = self._secret_scanner.scan(text)
        for finding in secrets:
            if finding["type"] == "high_entropy_token":
                weight = 0.30
            else:
                weight = 0.85
            evidences.append(
                DetectionEvidence(
                    detector_id=f"output.secret.{finding['type']}",
                    vector="secret_leak",
                    weight=weight,
                    triggered=True,
                    metadata={"finding": finding["type"]},
                )
            )

        return evidences

    def redact(self, text: str) -> str:
        secrets = self._secret_scanner.scan(text)
        if secrets:
            return self._secret_scanner.redact(text, secrets)
        return text
