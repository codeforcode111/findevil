from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLedger:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._counter = 0
        self._last_hash: str | None = None

        if self.path.exists():
            events = self.read_all()
            if events:
                self._counter = len(events)
                self._last_hash = events[-1]["hash"]

    def _compute_hash(self, record: dict[str, Any]) -> str:
        serialized = json.dumps(record, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def append(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        self._counter += 1
        record = {
            "event_id": f"evt-{self._counter:04d}",
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": self._last_hash,
            "data": data,
        }
        record["hash"] = self._compute_hash(record)
        self._last_hash = record["hash"]

        with open(self.path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text().strip().split("\n")
        return [json.loads(line) for line in lines if line.strip()]

    def verify_chain(self) -> bool:
        events = self.read_all()
        for i, event in enumerate(events):
            stored_hash = event.pop("hash")
            expected_hash = self._compute_hash(event)
            event["hash"] = stored_hash
            if stored_hash != expected_hash:
                return False
            if i == 0 and event["prev_hash"] is not None:
                return False
            if i > 0 and event["prev_hash"] != events[i - 1]["hash"]:
                return False
        return True

    def query(
        self,
        event_type: str | None = None,
        finding_id: str | None = None,
    ) -> list[dict[str, Any]]:
        results = []
        for event in self.read_all():
            if event_type and event["event_type"] != event_type:
                continue
            if finding_id and event["data"].get("finding_id") != finding_id:
                continue
            results.append(event)
        return results
