"""Persistent IBN state: intent records and IBN's view of every device's configuration.

Because the AI may use any technique, IBN keeps a full "shadow" running-config per device. It starts
from the synced running config (or a baseline rendered from the topology), and every deployment,
rollback or sync updates it. The validator works on this view.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from ibn.models.design import DeviceConfig
from ibn.models.intent import Intent


class IntentStatus(str, Enum):
    DEPLOYED = "deployed"
    WITHDRAWN = "withdrawn"


class IntentRecord(BaseModel):
    intent: Intent
    approach: str = ""
    devices: list[DeviceConfig] = Field(default_factory=list)  # what was deployed for this intent
    status: IntentStatus = IntentStatus.DEPLOYED
    plan_id: str | None = None
    updated_at: datetime | None = None


_records = TypeAdapter(list[IntentRecord])


class StateStore:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.intents_file = self.dir / "intents.json"
        self.configs_file = self.dir / "configs.json"

    def records(self) -> list[IntentRecord]:
        if not self.intents_file.is_file():
            return []
        try:
            return _records.validate_json(self.intents_file.read_text())
        except ValidationError:  # written by an older IBN version: keep it, start fresh
            self.intents_file.rename(self.intents_file.with_suffix(".legacy.json"))
            return []

    def active(self) -> list[IntentRecord]:
        return [r for r in self.records() if r.status == IntentStatus.DEPLOYED]

    def get(self, intent_id: str) -> IntentRecord | None:
        return next((r for r in self.records() if r.intent.id == intent_id), None)

    def stored_configs(self) -> dict[str, str]:
        if not self.configs_file.is_file():
            return {}
        return json.loads(self.configs_file.read_text())

    def configs(self, kb) -> dict[str, str]:
        """IBN's view of every device: stored shadow > synced running config > topology baseline."""
        from ibn.platforms import get_platform

        stored = self.stored_configs()
        out = {}
        for dev, info in kb.devices.items():
            out[dev] = stored.get(dev) or kb.running_config(dev) or get_platform(info.platform).baseline_config(kb, dev)
        return out

    def save(self, records: list[IntentRecord] | None = None, configs: dict[str, str] | None = None) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        if records is not None:
            self.intents_file.write_bytes(_records.dump_json(records, indent=2))
        if configs is not None:
            self.configs_file.write_text(json.dumps(configs, indent=2))

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        for f in (self.intents_file, self.configs_file):
            h.update(f.read_bytes() if f.is_file() else b"-")
        return h.hexdigest()[:16]
