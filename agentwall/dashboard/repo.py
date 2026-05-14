from __future__ import annotations

import aiosqlite


class EventsRepository:
    def __init__(self, db_path: str = "./agentwall_events.db") -> None:
        self._db_path = db_path

    async def get_stats(self, window_minutes: int = 60) -> dict:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT action, COUNT(*) as count FROM threat_events GROUP BY action"
            ) as cursor:
                rows = await cursor.fetchall()
            stats = {"blocked": 0, "sanitized": 0, "escalated": 0, "allowed": 0}
            for row in rows:
                action = row["action"]
                count = row["count"]
                if action == "BLOCK":
                    stats["blocked"] = count
                elif action == "SANITIZE":
                    stats["sanitized"] = count
                elif action == "ESCALATE":
                    stats["escalated"] = count
                elif action == "ALLOW":
                    stats["allowed"] = count
            return stats

    async def recent_events(self, limit: int = 50) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def events_by_vector(self, window_minutes: int = 60) -> list[dict]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT vector, severity, COUNT(*) as count "
                "FROM threat_events GROUP BY vector, severity"
            ) as cursor:
                rows = await cursor.fetchall()
            return [dict(r) for r in rows]
