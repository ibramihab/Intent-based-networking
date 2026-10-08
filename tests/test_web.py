import pytest
from fastapi.testclient import TestClient

from ibn.config import Settings
from ibn.web.app import create_app


@pytest.fixture
def client(root):
    return TestClient(create_app(lambda: Settings(root=root, gemini_api_key=None, gemini_model="test")))


def test_index_and_static_are_served(client):
    assert "IBN Console" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200


def test_full_flow_interpret_plan_deploy_withdraw(client):
    res = client.post("/api/interpret", json={"text": "block HR from reaching Finance on ssh", "offline": True}).json()
    assert res["parser"] == "offline" and not res["clarifications"]

    plan = client.post("/api/plans", json={"intents": res["intents"], "request": "x"}).json()
    assert plan["ok"] and plan["intents"][0]["solution"] == "acl" and plan["validation"]["passed"]
    assert any("ip access-group" in c for c in plan["candidate"]["changes"][0]["commands"])

    rep = client.post(f"/api/plans/{plan['plan_id']}/deploy", json={"live": False, "record_state": True}).json()
    assert rep["success"] and rep["dry_run"]

    records = client.get("/api/intents").json()
    assert records[0]["status"] == "deployed" and "DENY HR -> Finance" in records[0]["summary"]

    trace = client.post("/api/simulate", json={"src": "VPC4", "dst": "VPC5", "protocol": "tcp", "port": 22}).json()
    assert trace["allowed"] is False

    withdraw = client.post(f"/api/intents/{records[0]['intent']['id']}/withdraw").json()
    assert withdraw["ok"] and withdraw["kind"] == "withdraw"
    assert client.get("/api/history").json()[0]["event"] in ("plan", "deploy.end")


def test_conflict_can_be_resolved_by_raising_priority(client):
    deny = [{"description": "d", "action": "deny", "source": {"group": "HR"}, "destination": {"group": "Finance"},
             "services": [{"protocol": "tcp", "ports": [80]}]}]
    plan = client.post("/api/plans", json={"intents": deny, "request": "d"}).json()
    client.post(f"/api/plans/{plan['plan_id']}/deploy", json={"record_state": True})
    permit = [{**deny[0], "action": "permit"}]
    assert not client.post("/api/plans", json={"intents": permit, "request": "p"}).json()["ok"]
    raised = client.post("/api/plans", json={"intents": permit, "request": "p", "raise_priority": True}).json()
    assert raised["intents"][0]["priority"] == 110 and raised["ok"]


def test_errors_are_reported_cleanly(client):
    assert client.post("/api/plans/nope/deploy", json={}).status_code == 400
    assert client.post("/api/interpret", json={"text": "x", "conversation_id": "gone"}).status_code == 404
    assert client.post("/api/simulate", json={"src": "Sales", "dst": "VPC5"}).status_code == 400
    kb = client.get("/api/kb").json()
    assert kb["gemini"] is False and kb["issues"] == [] and len(kb["devices"]) == 5


class ScriptedLLM:
    """Stands in for Gemini: replies with queued JSON answers and records what it was told."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts = []

    def generate_json(self, system, messages):
        self.prompts.append((system, messages[-1]["text"]))
        return self.replies.pop(0)


def _llm_client(root, llm):
    settings = lambda: Settings(root=root, gemini_api_key="test", gemini_model="test")  # noqa: E731
    return TestClient(create_app(settings, provider_factory=lambda s: llm))


def _isolate(solution):
    return {"description": "isolate", "action": "deny", "source": {"group": "HR"},
            "destination": {"group": "Finance"}, "services": [{"protocol": "ip", "ports": []}],
            "bidirectional": True, "solution": solution, "solution_reason": f"{solution} because"}


def test_llm_chooses_solution_and_is_corrected_by_the_validator(root):
    llm = ScriptedLLM({"intents": [_isolate("vlan")], "clarifications": []},
                      {"intents": [_isolate("acl")], "clarifications": []})
    client = _llm_client(root, llm)
    res = client.post("/api/interpret", json={"text": "isolate HR and Finance"}).json()
    assert res["parser"] == "gemini" and res["conversation_id"]
    assert "Intents already deployed" in llm.prompts[0][0]

    plan = client.post("/api/plans", json={"intents": res["intents"], "request": "x",
                                           "conversation_id": res["conversation_id"]}).json()
    assert plan["ok"] and plan["intents"][0]["solution"] == "acl"
    assert plan["llm_feedback"][0]["solutions"] == ["vlan"]
    assert "routed subnets" in plan["llm_feedback"][0]["errors"][0]
    assert "rejected your intents" in llm.prompts[1][1]


def test_llm_clarification_keeps_the_conversation(root):
    llm = ScriptedLLM({"intents": [], "clarifications": ["Which direction?"]},
                      {"intents": [_isolate("acl")], "clarifications": []})
    client = _llm_client(root, llm)
    first = client.post("/api/interpret", json={"text": "block finance"}).json()
    assert first["clarifications"] == ["Which direction?"]
    second = client.post("/api/interpret", json={"text": "both", "conversation_id": first["conversation_id"]}).json()
    assert second["intents"][0]["solution"] == "acl"
    assert second["conversation_id"] == first["conversation_id"]
