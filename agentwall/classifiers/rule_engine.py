from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

import regex
import yaml
from rapidfuzz import fuzz

from agentwall.classifiers.base import Classifier
from agentwall.core.evidence import DetectionEvidence
from agentwall.core.payload import NormalizedPayload


class PatternEntry:
    def __init__(self, data: dict[str, Any]) -> None:
        self.id: str = data["id"]
        self.pattern: regex.Pattern = regex.compile(data["pattern"])
        self.plaintext: str = data.get("plaintext", "")
        self.weight: float = data.get("weight", 0.4)
        self.fuzzy_threshold: int = data.get("fuzzy_threshold", 85)
        self.severity_hint: str = data.get("severity_hint", "MEDIUM")
        self.vector: str = ""


class RuleEngineClassifier(Classifier):
    def __init__(self, pattern_path: Path | str | None = None) -> None:
        if pattern_path is None:
            path_obj = Path(
                str(files("agentwall.vectors.data") / "injection_patterns.yaml")
            )
        else:
            path_obj = Path(pattern_path) if isinstance(pattern_path, str) else pattern_path
        self._patterns: list[PatternEntry] = []
        self._load_patterns(path_obj)

    def _load_patterns(self, path: Path) -> None:
        if not path.exists():
            path = Path(
                str(files("agentwall.vectors.data") / "injection_patterns.yaml")
            )
        with open(path) as f:
            data = yaml.safe_load(f)
        for vector_name, patterns in data.get("vectors", {}).items():
            for p in patterns:
                entry = PatternEntry(p)
                entry.vector = vector_name
                self._patterns.append(entry)

    async def classify(
        self,
        payload: NormalizedPayload,
        variants: list[NormalizedPayload] | None = None,
    ) -> list[DetectionEvidence]:
        texts = [payload.text]
        if variants:
            texts.extend(v.text for v in variants if v.text != payload.text)

        evidences: list[DetectionEvidence] = []
        seen: set[str] = set()

        for pattern in self._patterns:
            if pattern.id in seen:
                continue
            matched = False
            for text in texts:
                if len(text) > 2000:
                    text = text[:2000]
                if pattern.pattern.search(text):
                    evidences.append(
                        DetectionEvidence(
                            detector_id=f"rule_engine.{pattern.vector}.{pattern.id}",
                            vector=pattern.vector,
                            weight=pattern.weight,
                            triggered=True,
                            raw_score=1.0,
                            metadata={"severity_hint": pattern.severity_hint},
                        )
                    )
                    seen.add(pattern.id)
                    matched = True
                    break
            if matched:
                continue
            fuzzy_text = payload.text[:2000] if len(payload.text) > 2000 else payload.text
            score = fuzz.partial_ratio(pattern.plaintext.lower(), fuzzy_text.lower())
            if score >= pattern.fuzzy_threshold:
                evidences.append(
                    DetectionEvidence(
                        detector_id=f"rule_engine.{pattern.vector}.{pattern.id}",
                        vector=pattern.vector,
                        weight=pattern.weight * 0.7,
                        triggered=True,
                        raw_score=score / 100.0,
                        metadata={"severity_hint": pattern.severity_hint, "fuzzy_score": score},
                    )
                )
                seen.add(pattern.id)

        return evidences
