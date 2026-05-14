import pytest
from pydantic import ValidationError

from agentwall.core.payload import NormalizedPayload


def test_normalized_payload_creation():
    payload = NormalizedPayload(
        text="Hello world",
        source="user_prompt",
        agent_id="test-agent",
    )
    assert payload.text == "Hello world"
    assert payload.source == "user_prompt"
    assert payload.agent_id == "test-agent"
    assert len(payload.correlation_id) == 32  # uuid4 hex


def test_normalized_payload_frozen():
    payload = NormalizedPayload(
        text="Hello",
        source="user_prompt",
        agent_id="test",
    )
    with pytest.raises(ValidationError):
        payload.text = "Modified"


def test_normalized_payload_roundtrip():
    payload = NormalizedPayload(
        text="Test",
        source="agent_message",
        agent_id="agent-1",
        metadata={"key": "value"},
    )
    json_str = payload.model_dump_json()
    restored = NormalizedPayload.model_validate_json(json_str)
    assert restored == payload


def test_normalized_payload_from_text():
    payload = NormalizedPayload.from_text(
        text="Hello",
        source="user_prompt",
        agent_id="agent-1",
    )
    assert payload.text == "Hello"
