from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml

from agentwall.policy.models import AgentPolicy

BUILTIN_POLICIES = {"strict", "moderate", "permissive"}


class PolicyValidationError(Exception):
    pass


def load_builtin(name: str) -> AgentPolicy:
    if name not in BUILTIN_POLICIES:
        raise PolicyValidationError(
            f"Unknown built-in policy: {name}. Available: {BUILTIN_POLICIES}"
        )
    path = files("agentwall.policy.builtin") / f"{name}.yaml"
    data = yaml.safe_load(path.read_text())
    try:
        return AgentPolicy.model_validate(data)
    except Exception as e:
        raise PolicyValidationError(f"Failed to parse built-in policy '{name}': {e}") from e


def load_from_path(path: Path | str) -> AgentPolicy:
    path = Path(path)
    if not path.exists():
        raise PolicyValidationError(f"Policy file not found: {path}")
    try:
        return AgentPolicy.from_yaml(str(path))
    except Exception as e:
        raise PolicyValidationError(f"Failed to parse policy file '{path}': {e}") from e


def load_policy(policy: str | Path | dict | AgentPolicy) -> AgentPolicy:
    if isinstance(policy, AgentPolicy):
        return policy
    if isinstance(policy, dict):
        return AgentPolicy.model_validate(policy)
    if isinstance(policy, Path):
        return load_from_path(policy)
    if isinstance(policy, str):
        path = Path(policy)
        if path.exists() and path.suffix in (".yaml", ".yml"):
            return load_from_path(path)
        if policy in BUILTIN_POLICIES:
            return load_builtin(policy)
        return load_from_path(path)
    raise PolicyValidationError(f"Cannot load policy from {type(policy)}")
