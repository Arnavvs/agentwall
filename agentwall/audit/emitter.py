from __future__ import annotations

import logging

from agentwall.core.event import ThreatEvent

logger = logging.getLogger(__name__)


class ThreatEventEmitter:
    def __init__(self, sinks: list[object] | None = None) -> None:
        self._sinks = sinks or []

    async def emit(self, event: ThreatEvent) -> None:
        for sink in self._sinks:
            try:
                if hasattr(sink, "emit"):
                    await sink.emit(event)
            except Exception:
                logger.exception("sink_emit_failed: %s", type(sink).__name__)
