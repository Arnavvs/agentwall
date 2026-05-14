from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParameterConstraint:
    allowed_prefixes: list[str] = field(default_factory=list)
    forbidden_substrings: list[str] = field(default_factory=list)
    max_length: int | None = None
    min_value: float | None = None
    max_value: float | None = None

    def check(self, value: str | int | float) -> tuple[bool, str]:
        str_value = str(value)
        if self.max_length and len(str_value) > self.max_length:
            return False, f"exceeds max_length {self.max_length}"
        for prefix in self.allowed_prefixes:
            if str_value.startswith(prefix):
                break
        else:
            if self.allowed_prefixes:
                return False, f"not in allowed_prefixes {self.allowed_prefixes}"
        for substr in self.forbidden_substrings:
            if substr in str_value:
                return False, f"contains forbidden_substring '{substr}'"
        if isinstance(value, (int, float)):
            if self.min_value is not None and value < self.min_value:
                return False, f"below min_value {self.min_value}"
            if self.max_value is not None and value > self.max_value:
                return False, f"above max_value {self.max_value}"
        return True, ""


@dataclass
class ToolPolicy:
    allowed_tools: list[str] = field(default_factory=list)
    forbidden_tools: list[str] = field(default_factory=list)
    parameter_constraints: dict[str, dict[str, ParameterConstraint]] = field(
        default_factory=dict
    )


@dataclass
class ScopeCheckResult:
    allowed: bool
    reason: str = ""


class ToolScopeEnforcer:
    def __init__(self, policies: dict[str, ToolPolicy] | None = None) -> None:
        self._policies = policies or {}

    def add_policy(self, agent_id: str, policy: ToolPolicy) -> None:
        self._policies[agent_id] = policy

    def check(
        self,
        tool_name: str,
        arguments: dict[str, object],
        agent_id: str = "default",
    ) -> ScopeCheckResult:
        policy = self._policies.get(agent_id)
        if policy is None:
            return ScopeCheckResult(allowed=True)

        if tool_name in policy.forbidden_tools:
            return ScopeCheckResult(allowed=False, reason="tool_explicitly_forbidden")

        if policy.allowed_tools and tool_name not in policy.allowed_tools:
            return ScopeCheckResult(allowed=False, reason="tool_not_in_allowlist")

        param_constraints = policy.parameter_constraints.get(tool_name)
        if param_constraints:
            for param_name, value in arguments.items():
                constraint = param_constraints.get(param_name)
                if constraint:
                    passed, reason = constraint.check(
                        value if isinstance(value, (str, int, float)) else str(value)
                    )
                    if not passed:
                        return ScopeCheckResult(
                            allowed=False,
                            reason=f"param_{param_name}_{reason}",
                        )

        return ScopeCheckResult(allowed=True)
