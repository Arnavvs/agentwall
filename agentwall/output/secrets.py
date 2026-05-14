from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from rapidfuzz import fuzz

from agentwall.normalizer.unicode import normalize_unicode

SECRET_PATTERNS = {
    "openai_api_key": r"sk-[a-zA-Z0-9]{20,}",
    "anthropic_api_key": r"sk-ant-[a-zA-Z0-9_\-]{20,}",
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{20,}",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{20,}",
    "private_key_block": r"-----BEGIN [A-Z ]+PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


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


class SecretScanner:
    def scan(self, text: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                findings.append(
                    {
                        "type": name,
                        "matched": match.group(),
                        "start": match.start(),
                        "end": match.end(),
                    }
                )
        for token in re.findall(r"[A-Za-z0-9+/=_\-]{20,}", text):
            if len(token) >= 20 and shannon_entropy(token) > 4.5:
                findings.append(
                    {
                        "type": "high_entropy_token",
                        "matched": token[:20] + "...",
                        "start": text.find(token),
                        "end": text.find(token) + len(token),
                    }
                )
        return findings

    def redact(self, text: str, findings: list[dict[str, Any]]) -> str:
        result = text
        for finding in sorted(findings, key=lambda f: f["start"], reverse=True):
            start = finding["start"]
            end = finding["end"]
            result = result[:start] + f"[REDACTED-{finding['type']}]" + result[end:]
        return result
