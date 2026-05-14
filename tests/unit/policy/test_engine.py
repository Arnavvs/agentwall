from agentwall.core.action import Action
from agentwall.core.severity import Severity
from agentwall.policy.engine import PolicyEngine


def test_engine_load_strict():
    engine = PolicyEngine("strict")
    assert engine.policy.metadata.name == "strict"


def test_engine_resolve_wildcard():
    engine = PolicyEngine("strict")
    spec = engine.resolve("unknown-agent")
    assert spec.vectors["prompt_injection"].enabled is True


def test_engine_action_block():
    engine = PolicyEngine("strict")
    action = engine.action_for("test-agent", "prompt_injection", Severity.HIGH)
    assert action == Action.BLOCK


def test_engine_action_allow_low():
    engine = PolicyEngine("strict")
    action = engine.action_for("test-agent", "prompt_injection", Severity.LOW)
    assert action == Action.ALLOW


def test_engine_action_permissive():
    engine = PolicyEngine("permissive")
    action = engine.action_for("test-agent", "prompt_injection", Severity.HIGH)
    assert action == Action.BLOCK
    action = engine.action_for("test-agent", "prompt_injection", Severity.LOW)
    assert action == Action.ALLOW


def test_engine_vector_enabled():
    engine = PolicyEngine("strict")
    assert engine.is_vector_enabled("test-agent", "prompt_injection") is True
    assert engine.is_vector_enabled("test-agent", "nonexistent") is False


def test_engine_override(sample_policy_path):
    import yaml

    path = sample_policy_path
    data = yaml.safe_load(path.read_text())
    data["spec"]["agent_overrides"] = {
        "special-agent": {
            "vectors": {
                "prompt_injection": {
                    "enabled": True,
                    "action": "SANITIZE",
                    "classifiers": ["rule_engine"],
                    "score_threshold": 0.5,
                }
            }
        }
    }
    path.write_text(yaml.dump(data))

    engine = PolicyEngine(str(path))
    spec = engine.resolve("special-agent")
    assert spec.vectors["prompt_injection"].action == Action.SANITIZE
