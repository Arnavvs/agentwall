import pytest
from pydantic import ValidationError

from agentwall.core.evidence import DetectionEvidence


def test_evidence_creation():
    ev = DetectionEvidence(
        detector_id="rule_engine.ignore_previous",
        vector="prompt_injection",
        weight=0.40,
        triggered=True,
    )
    assert ev.detector_id == "rule_engine.ignore_previous"
    assert ev.weight == 0.40
    assert ev.triggered is True


def test_evidence_weight_validation():
    with pytest.raises(ValidationError):
        DetectionEvidence(
            detector_id="test",
            vector="test",
            weight=1.5,
            triggered=True,
        )

    with pytest.raises(ValidationError):
        DetectionEvidence(
            detector_id="test",
            vector="test",
            weight=-0.1,
            triggered=True,
        )


def test_evidence_roundtrip():
    ev = DetectionEvidence(
        detector_id="prompt_shield.user_prompt",
        vector="prompt_injection",
        weight=0.55,
        triggered=True,
        raw_score=1.0,
        metadata={"latency_ms": 150},
    )
    json_str = ev.model_dump_json()
    restored = DetectionEvidence.model_validate_json(json_str)
    assert restored == ev
