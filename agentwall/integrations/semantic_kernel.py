from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def wrap_semantic_kernel(kernel: Any, pipeline: Any) -> Any:
    if getattr(kernel, "_agentwall_wrapped", False):
        return kernel

    try:
        from semantic_kernel.filters import FilterTypes

        @kernel.filter(FilterTypes.PROMPT_RENDERING)
        async def _inbound_filter(context: Any, next_filter: Any) -> None:
            await next_filter(context)
            text = getattr(context, "rendered_prompt", "") or ""
            if not text:
                return
            from agentwall.core.payload import NormalizedPayload

            payload = NormalizedPayload(
                text=text,
                source="user_prompt",
                agent_id=getattr(context.function, "fully_qualified_name", "sk_prompt"),
            )
            result = await pipeline.run_inbound(payload)
            if result.action.value == "BLOCK":
                context.rendered_prompt = (
                    f"Respond ONLY with: '[AgentWall blocked: {result.reason}]'"
                )
            else:
                context.rendered_prompt = result.payload.text

        @kernel.filter(FilterTypes.FUNCTION_INVOCATION)
        async def _function_filter(context: Any, next_filter: Any) -> None:
            tool_name = getattr(context.function, "name", "unknown")
            args_raw = getattr(context, "arguments", None)
            args = dict(args_raw) if args_raw else {}
            from agentwall.core.payload import NormalizedPayload

            payload = NormalizedPayload(
                text=str(args),
                source="tool_output",
                agent_id=getattr(context.function, "plugin_name", "default"),
                tool_name=tool_name,
            )
            result = await pipeline.run_inbound(payload)
            if result.action.value == "BLOCK":
                from semantic_kernel.functions import FunctionResult

                context.result = FunctionResult(
                    function=context.function.metadata,
                    value=f"[AgentWall blocked tool {tool_name}: {result.reason}]",
                )
                return
            await next_filter(context)

        kernel._agentwall_wrapped = True
        kernel._agentwall_pipeline = pipeline
    except ImportError:
        logger.warning("Semantic Kernel not available, skipping filter registration")
        kernel._agentwall_wrapped = True

    return kernel
