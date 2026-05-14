from __future__ import annotations

from copy import deepcopy

from agentwall.core.action import Action
from agentwall.core.severity import Severity
from agentwall.policy.loader import load_policy
from agentwall.policy.models import AgentPolicy, AgentSpec, VectorConfig


def _deep_merge(base: dict, override: dict) -> dict:
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


class PolicyEngine:
    def __init__(self, policy: str | AgentPolicy) -> None:
        self._policy = load_policy(policy) if isinstance(policy, str) else policy
        self._cache: dict[str, AgentSpec] = {}

    @property
    def policy(self) -> AgentPolicy:
        return self._policy

    def resolve(self, agent_id: str) -> AgentSpec:
        if agent_id in self._cache:
            return self._cache[agent_id]

        wildcard = self._policy.spec.agents.get("*")
        if wildcard is None:
            raise ValueError(f"No wildcard agent config in policy and no config for '{agent_id}'")

        override = self._policy.spec.agent_overrides.get(agent_id, {})
        if override:
            base_dict = wildcard.model_dump()
            merged = _deep_merge(base_dict, override)
            resolved = AgentSpec.model_validate(merged)
        else:
            resolved = wildcard

        self._cache[agent_id] = resolved
        return resolved

    def action_for(self, agent_id: str, vector: str, severity: Severity) -> Action:
        spec = self.resolve(agent_id)
        vector_config = spec.vectors.get(vector)
        if vector_config is None or not vector_config.enabled:
            return Action.ALLOW
        if severity < Severity.MEDIUM and vector_config.action == Action.BLOCK:
            if severity == Severity.LOW:
                return Action.ALLOW
        return vector_config.action

    def get_vector_config(self, agent_id: str, vector: str) -> VectorConfig | None:
        spec = self.resolve(agent_id)
        return spec.vectors.get(vector)

    def is_vector_enabled(self, agent_id: str, vector: str) -> bool:
        config = self.get_vector_config(agent_id, vector)
        return config is not None and config.enabled
