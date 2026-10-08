"""Persistent IBN state: intent records and the managed config state of every device."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, TypeAdapter

from ibn.models.intent import Intent, SolutionKind
from ibn.models.netconfig import DeviceState


class IntentStatus(str, Enum):
    DEPLOYED = "deployed"
    WITHDRAWN = "withdrawn"


class IntentRecord(BaseModel):
    intent: Intent
    solution: SolutionKind
    status: IntentStatus = IntentStatus.DEPLOYED
    plan_id: str | None = None
    updated_at: datetime | None = None


_records = TypeAdapter(list[IntentRecord])
_managed = TypeAdapter(dict[str, DeviceState])


class StateStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.intents_file = self.dir / "intents.json"
        self.managed_file = self.dir / "managed.json"

    def records(self) -> list[IntentRecord]:
        if not self.intents_file.is_file():
            return []
        return _records.validate_json(self.intents_file.read_text())

    def active(self) -> list[IntentRecord]:
        return [r for r in self.records() if r.status == IntentStatus.DEPLOYED]

    def get(self, intent_id: str) -> IntentRecord | None:
        return next((r for r in self.records() if r.intent.id == intent_id), None)

    def managed(self) -> dict[str, DeviceState]:
        if not self.managed_file.is_file():
            return {}
        return _managed.validate_json(self.managed_file.read_text())

    def save(self, records: list[IntentRecord], managed: dict[str, DeviceState]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self.intents_file.write_bytes(_records.dump_json(records, indent=2))
        self.managed_file.write_bytes(_managed.dump_json(managed, indent=2))

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        for f in (self.intents_file, self.managed_file):
            h.update(f.read_bytes() if f.is_file() else b"-")
        return h.hexdigest()[:16]


def dump(obj) -> str:
    """Stable JSON for pydantic models / plain data."""
    if isinstance(obj, BaseModel):
        return obj.model_dump_json(indent=2)
    return json.dumps(obj, indent=2, default=str)
