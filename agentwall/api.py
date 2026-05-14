from __future__ import annotations

import logging
from typing import Any

from agentwall.audit.emitter import ThreatEventEmitter
from agentwall.classifiers.rule_engine import RuleEngineClassifier
from agentwall.core.pipeline import Pipeline
from agentwall.integrations.autogen_v04 import (
    _is_autogen_v02,
    _is_autogen_v04,
    _is_sk_kernel,
    wrap_autogen_v04,
)
from agentwall.policy.engine import PolicyEngine
from agentwall.scoring.scorer import ThreatScorer

logger = logging.getLogger(__name__)


class UnsupportedAgentError(Exception):
    pass


class AgentWall:
    @staticmethod
    def wrap(agent: Any, policy: str = "strict") -> Any:
        if getattr(agent, "_agentwall_wrapped", False):
            return agent

        policy_engine = PolicyEngine(policy)
        classifiers: list[Any] = [RuleEngineClassifier()]
        scorer = ThreatScorer()
        audit = ThreatEventEmitter()

        pipeline = Pipeline(
            policy_engine=policy_engine,
            classifiers=classifiers,
            scorer=scorer,
            audit_emitter=audit,
        )

        if _is_autogen_v04(agent):
            return wrap_autogen_v04(agent, pipeline)
        elif _is_autogen_v02(agent):
            return _wrap_autogen_v02(agent, pipeline)
        elif _is_sk_kernel(agent):
            return _wrap_sk_kernel(agent, pipeline)
        else:
            return _wrap_generic(agent, pipeline)


def _wrap_autogen_v02(agent: Any, pipeline: Any) -> Any:
    if getattr(agent, "_agentwall_wrapped", False):
        return agent

    import asyncio

    def inbound_hook(message: Any, sender: Any, recipient: Any, silent: bool) -> str:
        loop = asyncio.new_event_loop()
        try:
            from agentwall.core.payload import NormalizedPayload

            text = str(message) if not isinstance(message, str) else message
            payload = NormalizedPayload(
                text=text,
                source="user_prompt",
                agent_id=getattr(agent, "name", "unknown"),
            )
            result = loop.run_until_complete(pipeline.run_inbound(payload))
            if result.action.value == "BLOCK":
                return f"[blocked by AgentWall: {result.reason}]"
            return result.payload.text  # type: ignore[no-any-return]
        finally:
            loop.close()

    def outbound_hook(message: Any, recipient: Any, silent: bool) -> str:
        loop = asyncio.new_event_loop()
        try:
            from agentwall.core.payload import NormalizedPayload

            text = str(message) if not isinstance(message, str) else message
            payload = NormalizedPayload(
                text=text,
                source="outbound_response",
                agent_id=getattr(agent, "name", "unknown"),
            )
            result = loop.run_until_complete(pipeline.run_outbound(payload))
            if result.action.value == "BLOCK":
                return "[redacted by AgentWall]"
            return result.payload.text  # type: ignore[no-any-return]
        finally:
            loop.close()

    try:
        agent.register_hook("process_last_received_message", inbound_hook)
        agent.register_hook("process_message_before_send", outbound_hook)
    except AttributeError:
        logger.warning("AutoGen v02 hook registration failed, falling back to generic wrap")
        return _wrap_generic(agent, pipeline)

    agent._agentwall_wrapped = True
    return agent


def _wrap_sk_kernel(agent: Any, pipeline: Any) -> Any:
    if getattr(agent, "_agentwall_wrapped", False):
        return agent
    agent._agentwall_wrapped = True
    agent._agentwall_pipeline = pipeline
    return agent


def _wrap_generic(agent: Any, pipeline: Any) -> Any:
    agent._agentwall_wrapped = True
    agent._agentwall_pipeline = pipeline
    return agent


def wrap(agent: Any, policy: str = "strict") -> Any:
    return AgentWall.wrap(agent, policy)
