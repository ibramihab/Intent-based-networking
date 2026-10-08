import copy
import shutil
from pathlib import Path

import pytest

from ibn.config import Settings
from ibn.intent.agent import IntentAgent
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


class ScriptedLLM:
    """Stands in for Gemini: answers with queued JSON replies and records every prompt."""

    def __init__(self, *replies, review=None):
        self.replies = list(replies)
        self.review = review or {"verdict": "approve", "findings": []}
        self.prompts = []

    def generate_json(self, system, messages):
        self.prompts.append((system, messages[-1]["text"]))
        if "independent senior network engineer" in system:
            return copy.deepcopy(self.review)
        return copy.deepcopy(self.replies.pop(0))


def agent_for(kb, *replies, review=None):
    llm = ScriptedLLM(*replies, review=review)
    return IntentAgent(llm, kb), llm


def intent(description="Block SSH from HR to Finance", expectations=None, **kw):
    if expectations is None:
        expectations = [
            {"src": "HR", "dst": "Finance", "protocol": "tcp", "port": 22, "expect": "deny"},
            {"src": "HR", "dst": "Finance", "protocol": "tcp", "port": 80, "expect": "allow"},
            {"src": "HR", "dst": "Finance", "protocol": "icmp", "expect": "allow"},
        ]
    return {"description": description, "category": "access-control", "requirements": ["no ssh"],
            "scope": {"groups": ["HR", "Finance"]}, "expectations": expectations, **kw}


ACL_COMMANDS = [
    "ip access-list extended IBN_HR_IN",
    " 10 deny tcp 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255 eq 22",
    " 20 permit ip any any",
    "interface Ethernet0/2",
    " ip access-group IBN_HR_IN in",
]
ACL_ROLLBACK = ["interface Ethernet0/2", " no ip access-group IBN_HR_IN in", "no ip access-list extended IBN_HR_IN"]


def design(commands=None, rollback=None, device="R1", verify=None, approach="extended ACL", **kw):
    return {
        "approach": approach,
        "reasoning": "closest to the source",
        "neutral_model": [{"device": device, "type": "traffic-filter", "name": "IBN_HR_IN"}],
        "devices": [{
            "device": device,
            "commands": ACL_COMMANDS if commands is None else commands,
            "rollback": ACL_ROLLBACK if rollback is None else rollback,
            "verify": verify if verify is not None else [
                {"command": "show ip access-lists IBN_HR_IN", "expect_contains": ["IBN_HR_IN"]}],
        }],
        **kw,
    }
