from __future__ import annotations

import logging

from agentwall.core.event import ThreatEvent

logger = logging.getLogger(__name__)


class SentinelSink:
    def __init__(
        self,
        dce_endpoint: str = "",
        dcr_immutable_id: str = "",
        stream_name: str = "Custom-AgentWallThreats_CL",
    ) -> None:
        self._dce_endpoint = dce_endpoint
        self._dcr_immutable_id = dcr_immutable_id
        self._stream_name = stream_name
        self._available = bool(dce_endpoint and dcr_immutable_id)

    async def emit(self, event: ThreatEvent) -> None:
        if not self._available:
            logger.debug("Sentinel sink not configured, skipping")
            return
        logger.info("Sentinel event: %s %s", event.severity, event.vector)
