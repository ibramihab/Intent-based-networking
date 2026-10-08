"""Runtime settings. Secrets come from the environment (or a local, git-ignored .env)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_GEMINI_MODEL = "gemini-flash-latest"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    root: Path
    gemini_api_key: str | None
    gemini_model: str

    @property
    def kb_dir(self) -> Path:
        return self.root / "kb"

    @property
    def state_dir(self) -> Path:
        return self.kb_dir / "state"

    @property
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

    @property
    def backups_dir(self) -> Path:
        return self.root / "backups"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"


def load_settings(root: str | Path | None = None) -> Settings:
    base = Path(root or os.environ.get("IBN_HOME") or Path.cwd()).resolve()
    _load_dotenv(base / ".env")
    return Settings(
        root=base,
        gemini_api_key=os.environ.get("GEMINI_API_KEY"),
        gemini_model=os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
    )
