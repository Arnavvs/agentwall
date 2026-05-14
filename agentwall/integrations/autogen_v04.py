from __future__ import annotations

import inspect
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _is_autogen_v04(agent: object) -> bool:
    try:
        from autogen_agentchat.agents import AssistantAgent
        return isinstance(agent, AssistantAgent)
    except ImportError:
        return False


def _is_autogen_v02(agent: object) -> bool:
    try:
        from autogen import ConversableAgent
        return isinstance(agent, ConversableAgent)
    except ImportError:
        return False


def _is_sk_kernel(agent: object) -> bool:
    try:
        from semantic_kernel import Kernel
        return isinstance(agent, Kernel)
    except ImportError:
        return False


def wrap_autogen_v04(agent: Any, pipeline: Any) -> Any:
    if getattr(agent, "_agentwall_wrapped", False):
        return agent

    original_on_messages = agent.on_messages
    sig = inspect.signature(original_on_messages)

    async def patched(*args: Any, **kwargs: Any) -> Any:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        messages = bound.arguments.get("messages", [])

        cleaned = []
        for msg in messages:
            text = _extract_text_from_autogen_msg(msg)
            if text is None:
                cleaned.append(msg)
                continue

            from agentwall.core.payload import NormalizedPayload

            payload = NormalizedPayload(
                text=text,
                source="user_prompt",
                agent_id=getattr(agent, "name", "unknown"),
            )
            result = await pipeline.run_inbound(payload)
            if result.action.value == "BLOCK":
                from autogen_agentchat.base import Response
                from autogen_agentchat.messages import TextMessage

                return Response(
                    chat_message=TextMessage(
                        content=f"[AgentWall blocked: {result.reason}]",
                        source="agentwall",
                    )
                )
            cleaned.append(msg)

        response = await original_on_messages(*bound.args, **bound.kwargs)
        return response

    agent.on_messages = patched
    agent._agentwall_wrapped = True
    agent._agentwall_pipeline = pipeline
    return agent


def _extract_text_from_autogen_msg(msg: Any) -> str | None:
    if isinstance(msg, str):
        return msg
    if hasattr(msg, "content"):
        return str(msg.content)
    if hasattr(msg, "text"):
        return str(msg.text)
    if isinstance(msg, dict):
        val = msg.get("content") or msg.get("text")
        return str(val) if val else None
    return None
