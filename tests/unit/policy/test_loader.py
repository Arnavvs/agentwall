import pytest

from agentwall.policy.loader import PolicyValidationError, load_builtin, load_policy


def test_load_builtin_strict():
    policy = load_builtin("strict")
    assert policy.metadata.name == "strict"
    assert "*" in policy.spec.agents


def test_load_builtin_moderate():
    policy = load_builtin("moderate")
    assert policy.metadata.name == "moderate"


def test_load_builtin_permissive():
    policy = load_builtin("permissive")
    assert policy.metadata.name == "permissive"


def test_load_builtin_invalid():
    with pytest.raises(PolicyValidationError):
        load_builtin("nonexistent")


def test_load_policy_from_string():
    policy = load_policy("strict")
    assert policy.metadata.name == "strict"


def test_load_policy_from_path(sample_policy_path):
    policy = load_policy(sample_policy_path)
    assert policy.metadata.name == "test"


def test_load_policy_from_dict():
    data = {
        "apiVersion": "agentwall.dev/v1",
        "kind": "AgentPolicy",
        "metadata": {"name": "inline", "description": "test"},
        "spec": {
            "agents": {
                "*": {
                    "vectors": {
                        "prompt_injection": {
                            "enabled": True,
                            "action": "BLOCK",
                            "classifiers": ["rule_engine"],
                            "score_threshold": 0.5,
                        }
                    },
                    "output_validation": {},
                    "escalation": {},
                    "audit": {},
                }
            },
            "agent_overrides": {},
        },
    }
    policy = load_policy(data)
    assert policy.metadata.name == "inline"
