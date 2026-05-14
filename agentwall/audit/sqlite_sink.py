from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

from agentwall.core.event import ThreatEvent

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    vector TEXT NOT NULL,
    severity TEXT NOT NULL,
    action TEXT NOT NULL,
    threat_score REAL NOT NULL,
    payload_hash TEXT,
    payload_preview TEXT,
    metadata_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_timestamp ON threat_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_severity ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_agent ON threat_events(agent_id);
"""


class SQLiteSink:
    def __init__(self, db_path: str | Path = "./agentwall_events.db") -> None:
        self._db_path = str(db_path)
        self._initialized = False

    async def _ensure_schema(self) -> None:
        if self._initialized:
            return
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(_SCHEMA)
            await db.commit()
        self._initialized = True

    async def emit(self, event: ThreatEvent) -> None:
        await self._ensure_schema()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO threat_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(event.event_id),
                    event.timestamp.isoformat(),
                    event.agent_id,
                    event.vector,
                    event.severity.value,
                    event.action.value,
                    event.threat_score,
                    event.payload_hash,
                    event.payload_preview,
                    json.dumps(event.metadata),
                ),
            )
            await db.commit()
