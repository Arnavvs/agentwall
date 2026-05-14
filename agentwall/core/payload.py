from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class NormalizedPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    text: str
    source: Literal[
        "user_prompt",
        "agent_message",
        "tool_output",
        "mcp_payload",
        "rag_document",
        "outbound_response",
    ]
    agent_id: str
    correlation_id: str = Field(default_factory=lambda: uuid4().hex)
    tool_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_text(
        cls,
        text: str,
        source: Literal[
            "user_prompt",
            "agent_message",
            "tool_output",
            "mcp_payload",
            "rag_document",
            "outbound_response",
        ],
        agent_id: str,
        **kwargs: Any,
    ) -> NormalizedPayload:
        return cls(text=text, source=source, agent_id=agent_id, **kwargs)
