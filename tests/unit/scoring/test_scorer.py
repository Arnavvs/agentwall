from agentwall.core.evidence import DetectionEvidence
from agentwall.core.severity import Severity
from agentwall.scoring.scorer import ThreatScorer


def test_scorer_empty():
    scorer = ThreatScorer()
    result = scorer.score([])
    assert result.severity == Severity.SAFE
    assert result.score == 0.0


def test_scorer_single_evidence():
    scorer = ThreatScorer()
    ev = DetectionEvidence(
        detector_id="rule_engine.prompt_injection.ignore_previous",
        vector="prompt_injection",
        weight=0.40,
        triggered=True,
    )
    result = scorer.score([ev])
    assert result.severity == Severity.MEDIUM
    assert result.score == 0.40


def test_scorer_two_evidences():
    scorer = ThreatScorer()
    ev1 = DetectionEvidence(
        detector_id="prompt_shield.user_prompt",
        vector="prompt_injection",
        weight=0.55,
        triggered=True,
    )
    ev2 = DetectionEvidence(
        detector_id="rule_engine.prompt_injection.ignore_previous",
        vector="prompt_injection",
        weight=0.40,
        triggered=True,
    )
    result = scorer.score([ev1, ev2])
    expected = 1 - (1 - 0.55) * (1 - 0.40)
    assert abs(result.score - expected) < 0.01
    assert result.severity == Severity.HIGH


def test_scorer_critical():
    scorer = ThreatScorer()
    ev = DetectionEvidence(
        detector_id="prompt_shield.user_prompt",
        vector="prompt_injection",
        weight=0.55,
        triggered=True,
        raw_score=1.0,
    )
    ev2 = DetectionEvidence(
        detector_id="rule_engine.prompt_injection.ignore_previous",
        vector="prompt_injection",
        weight=0.40,
        triggered=True,
        raw_score=1.0,
    )
    ev3 = DetectionEvidence(
        detector_id="ai_language",
        vector="prompt_injection",
        weight=0.30,
        triggered=True,
        raw_score=1.0,
    )
    result = scorer.score([ev, ev2, ev3])
    assert result.severity == Severity.HIGH
    assert result.score >= 0.65


def test_scorer_no_triggered():
    scorer = ThreatScorer()
    ev = DetectionEvidence(
        detector_id="rule_engine.prompt_injection.ignore_previous",
        vector="prompt_injection",
        weight=0.40,
        triggered=False,
    )
    result = scorer.score([ev])
    assert result.severity == Severity.SAFE


def test_scorer_weight_override():
    scorer = ThreatScorer(weight_overrides={"prompt_shield.user_prompt": 0.80})
    ev = DetectionEvidence(
        detector_id="prompt_shield.user_prompt",
        vector="prompt_injection",
        weight=0.55,
        triggered=True,
    )
    result = scorer.score([ev])
    assert result.score == 0.80
