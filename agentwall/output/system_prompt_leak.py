from __future__ import annotations

from rapidfuzz import fuzz

from agentwall.normalizer.unicode import normalize_unicode


class SystemPromptLeakDetector:
    def __init__(self, system_prompt: str, threshold: int = 80) -> None:
        self.system_prompt = system_prompt
        self.threshold = threshold
        self.normalized = normalize_unicode(system_prompt)

    def check(self, output: str) -> bool:
        normalized_output = normalize_unicode(output)
        for chunk_size in [50, 100, 200]:
            if len(self.normalized) < chunk_size:
                continue
            for i in range(0, len(self.normalized) - chunk_size, chunk_size // 2):
                chunk = self.normalized[i : i + chunk_size]
                if chunk in normalized_output:
                    return True
        return fuzz.partial_ratio(self.normalized, normalized_output) >= self.threshold
