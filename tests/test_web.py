import pytest
from fastapi.testclient import TestClient

from ibn.config import Settings
from ibn.web.app import create_app
from tests.conftest import ScriptedLLM, design, intent


@pytest.fixture
def no_ai(root):
    return TestClient(create_app(lambda: Settings(root=root, gemini_api_key=None, gemini_model="test")))


def ai_client(root, llm):
    settings = lambda: Settings(root=root, gemini_api_key="test", gemini_model="test")  # noqa: E731
    return TestClient(create_app(settings, provider_factory=lambda s: llm))


def test_index_and_static_are_served(no_ai):
    assert "IBN Console" in no_ai.get("/").text
    assert no_ai.get("/static/app.js").status_code == 200


def test_ai_is_required(no_ai):
    res = no_ai.post("/api/interpret", json={"text": "block ssh"})
    assert res.status_code == 400 and "GEMINI_API_KEY" in res.json()["detail"]
    kb = no_ai.get("/api/kb").json()
    assert kb["gemini"] is False and kb["issues"] == [] and "hostname R1" in kb["configs"]["R1"]


def test_full_flow_with_clarification_redesign_deploy_and_withdraw(root):
    broken = design(rollback=[])
    llm = ScriptedLLM(
        {"intents": [], "clarifications": ["Should Finance still reach HR over SSH?"]},
        {"intents": [intent()], "clarifications": []},
        broken, design(),  # first design is rejected (no rollback), the second passes
        {"approach": "remove ACL", "reasoning": "withdraw", "neutral_model": [],
         "devices": [{"device": "R1", "commands": ["interface Ethernet0/2", " no ip access-group IBN_HR_IN in",
                                                   "no ip access-list extended IBN_HR_IN"],
                      "rollback": ["ip access-list extended IBN_HR_IN",
                                   " 10 deny tcp 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255 eq 22", " 20 permit ip any any",
                                   "interface Ethernet0/2", " ip access-group IBN_HR_IN in"],
                      "verify": [{"command": "show ip access-lists", "expect_absent": ["IBN_HR_IN"]}]}]},
    )
    client = ai_client(root, llm)
    first = client.post("/api/interpret", json={"text": "block ssh from HR to finance"}).json()
    assert first["clarifications"]
    second = client.post("/api/interpret", json={"text": "yes", "conversation_id": first["conversation_id"]}).json()
    assert second["intents"][0]["expectations"][0]["port"] == 22

    plan = client.post("/api/plans", json={"intents": second["intents"], "request": "block ssh",
                                           "conversation_id": second["conversation_id"]}).json()
    assert plan["ok"] and len(plan["attempts"]) == 2 and "no rollback" in plan["attempts"][0]["errors"][0]
    assert "configs_after" not in plan

    rep = client.post(f"/api/plans/{plan['plan_id']}/deploy", json={"record_state": True}).json()
    assert rep["success"] and rep["dry_run"]
    records = client.get("/api/intents").json()
    assert records[0]["status"] == "deployed" and records[0]["approach"] == "extended ACL"

    trace = client.post("/api/simulate", json={"src": "VPC4", "dst": "VPC5", "protocol": "tcp", "port": 22}).json()
    assert trace["allowed"] is False and "IBN_HR_IN" in " ".join(trace["trace"])

    withdraw = client.post(f"/api/intents/{records[0]['intent']['id']}/withdraw").json()
    assert withdraw["ok"] and withdraw["kind"] == "withdraw" and withdraw["design"]["approach"] == "remove ACL"
    assert client.get("/api/history").json()[0]["event"] == "plan"


def test_override_needs_confirmation(root):
    allow = intent(description="allow ssh", expectations=[
        {"src": "HR", "dst": "Finance", "protocol": "tcp", "port": 22, "expect": "allow"}])
    opener = design(commands=["ip access-list extended IBN_HR_IN", " 5 permit tcp 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255 eq 22"],
                    rollback=["ip access-list extended IBN_HR_IN", " no 5"])
    llm = ScriptedLLM(design(), opener)
    client = ai_client(root, llm)
    plan = client.post("/api/plans", json={"intents": [intent()], "request": "block"}).json()
    client.post(f"/api/plans/{plan['plan_id']}/deploy", json={"record_state": True})
    refused = client.post("/api/plans", json={"intents": [allow], "request": "allow"}).json()
    assert not refused["ok"] and refused["design"] is None
    confirmed = client.post("/api/plans", json={"intents": [allow], "request": "allow", "override": True}).json()
    assert confirmed["intents"][0]["priority"] == 110 and confirmed["ok"], confirmed["validation"]


def test_errors_are_reported_cleanly(no_ai):
    assert no_ai.post("/api/plans/nope/deploy", json={}).status_code == 400
    assert no_ai.post("/api/interpret", json={"text": "x", "conversation_id": "gone"}).status_code == 404
    assert no_ai.post("/api/simulate", json={"src": "Sales", "dst": "VPC5"}).status_code == 400
