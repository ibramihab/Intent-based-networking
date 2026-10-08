"""Append-only audit log (JSON lines)."""

from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)

    def write(self, event: str, **data: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            user = getpass.getuser()
        except Exception:
            user = "unknown"
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "user": user, "event": event, **data}
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")

    def read(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        return [json.loads(ln) for ln in self.path.read_text().splitlines()[-limit:]]
