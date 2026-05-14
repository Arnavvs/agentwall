from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from agentwall.core.action import Action


class PolicyMetadata(BaseModel):
    name: str
    description: str = ""


class VectorConfig(BaseModel):
    enabled: bool = True
    action: Action = Action.BLOCK
    classifiers: list[str] = Field(default_factory=list)
    score_threshold: float = 0.5


class OutputValidationConfig(BaseModel):
    enabled: bool = True
    action: Action = Action.REDACT
    detectors: dict[str, Any] = Field(default_factory=dict)


class EscalationConfig(BaseModel):
    sentinel_min_severity: str = "HIGH"
    alert_threshold: dict[str, int] = Field(
        default_factory=lambda: {"count": 3, "window_seconds": 60}
    )


class AuditConfig(BaseModel):
    log_all_events: bool = True
    log_payloads: bool = False
    retention_days: int = 30
    app_insights_connection_string: str = ""
    local_db_path: str = ""
    sentinel_enabled: bool = False
    sentinel_dce_endpoint: str = ""
    sentinel_dcr_immutable_id: str = ""
    sentinel_stream_name: str = "Custom-AgentWallThreats_CL"


class AgentSpec(BaseModel):
    vectors: dict[str, VectorConfig]
    output_validation: OutputValidationConfig = Field(default_factory=OutputValidationConfig)
    escalation: EscalationConfig = Field(default_factory=EscalationConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)


class PolicySpec(BaseModel):
    agents: dict[str, AgentSpec]
    agent_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)


class AgentPolicy(BaseModel):
    apiVersion: str  # noqa: N815
    kind: str
    metadata: PolicyMetadata
    spec: PolicySpec

    @classmethod
    def from_yaml(cls, path: str) -> AgentPolicy:
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.model_validate(data)
