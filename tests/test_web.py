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
    assert plan["ok"] and plan["chosen"] == "acl" and plan["validation"]["passed"]
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
