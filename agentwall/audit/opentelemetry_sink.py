from __future__ import annotations

import logging

from agentwall.core.event import ThreatEvent

logger = logging.getLogger(__name__)


class OpenTelemetrySink:
    def __init__(self, connection_string: str = "") -> None:
        self._connection_string = connection_string
        self._available = bool(connection_string)

    async def emit(self, event: ThreatEvent) -> None:
        if not self._available:
            logger.debug("OpenTelemetry sink not configured, skipping")
            return
        logger.info("OTel event: %s %s", event.severity, event.vector)
