import shutil
from pathlib import Path

import pytest

from ibn.config import Settings
from ibn.kb.knowledge_base import KnowledgeBase
from ibn.pipeline import IBN

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def root(tmp_path: Path) -> Path:
    kb = tmp_path / "kb"
    kb.mkdir()
    for name in ("inventory.yaml", "topology.yaml", "policies.yaml"):
        shutil.copy(REPO / "kb" / name, kb / name)
    (kb / "configs").mkdir()
    return tmp_path


@pytest.fixture
def kb(root: Path) -> KnowledgeBase:
    return KnowledgeBase(root / "kb")


@pytest.fixture
def ibn(root: Path) -> IBN:
    return IBN(Settings(root=root, gemini_api_key=None, gemini_model="test"))


def intent(action="deny", src=None, dst=None, services=None, **kw):
    return {"description": "test", "action": action, "source": src or {"group": "HR"},
            "destination": dst or {"group": "Finance"},
            "services": services or [{"protocol": "ip", "ports": []}], **kw}
