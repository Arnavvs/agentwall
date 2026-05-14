from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DetectionEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    detector_id: str
    vector: str
    weight: float
    triggered: bool
    raw_score: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("weight")
    @classmethod
    def weight_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"weight must be between 0.0 and 1.0, got {v}")
        return v
