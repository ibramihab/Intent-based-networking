import pytest

from ibn.control.connection import DryRunConnection
from ibn.control.verifier import Probe
from ibn.pipeline import PlanError
from tests.conftest import ACL_COMMANDS, agent_for, design, intent


class FailingConnection(DryRunConnection):
    """Rejects configuration on one device, to exercise staged rollback."""

    fail_on = "R3"

    def send_config(self, commands):
        super().send_config(commands)
        rollback = any(c.lstrip().startswith("no ") for c in commands)
        return "% Invalid input detected at '^' marker." if self.name == self.fail_on and not rollback else ""


def test_plan_deploy_withdraw_with_ai(ibn):
    agent, llm = agent_for(ibn.kb, design())
    plan = ibn.plan_submit([intent()], "block ssh", agent)
    assert plan.ok and plan.design.approach == "extended ACL" and len(plan.attempts) == 1
    assert "Intents already deployed" in llm.prompts[0][0] or "Current configuration" in llm.prompts[0][0]
    assert (ibn.package_dir(plan.plan_id) / "configs" / "R1.txt").read_text().startswith("ip access-list")

    rep = ibn.deploy(plan.plan_id, dry_run=True, record_state=True)
    assert rep.success and rep.devices[0].backup
    record = ibn.store.active()[0]
    assert record.approach == "extended ACL" and record.devices[0].commands == ACL_COMMANDS
    assert " ip access-group IBN_HR_IN in" in ibn.configs()["R1"]  # IBN's view now includes the change

    withdraw = ibn.plan_withdraw(record.intent.id, agent=None)  # no AI: stored rollback is replayed
    assert withdraw.ok, withdraw.validation.to_markdown()
    ibn.deploy(withdraw.plan_id, dry_run=True, record_state=True)
    assert ibn.store.active() == [] and "IBN_HR_IN" not in ibn.configs()["R1"]


def test_validator_feedback_loop_reaches_the_ai(ibn):
    broken = design(commands=[c.replace("0.0.0.255 eq 22", "0.0.3.255 eq 22") for c in ACL_COMMANDS])
    agent, llm = agent_for(ibn.kb, broken, design())
    plan = ibn.plan_submit([intent()], "block ssh", agent)
    assert plan.ok and len(plan.attempts) == 2
    assert "wildcard" in plan.attempts[0].errors[0]
    assert "Validation Layer rejected your design" in llm.prompts[-2][1] or \
        any("rejected your design" in p[1] for p in llm.prompts)


def test_gives_up_after_max_attempts(ibn):
    bad = design(rollback=[])
    agent, _ = agent_for(ibn.kb, bad, bad, bad)
    plan = ibn.plan_submit([intent()], "x", agent)
    assert not plan.ok and len(plan.attempts) == ibn.kb.policies.max_design_attempts


def test_without_ai_no_design(ibn):
    plan = ibn.plan_submit([intent()], "x", None)
    assert not plan.ok and "GEMINI_API_KEY" in plan.design_error


def test_stale_plan_is_refused(ibn):
    a1, _ = agent_for(ibn.kb, design())
    a2, _ = agent_for(ibn.kb, design(device="R3", commands=["ip access-list extended IBN_FIN_IN",
                                                            " deny tcp any any eq 23", " permit ip any any",
                                                            "interface Ethernet0/2", " ip access-group IBN_FIN_IN in"],
                                     rollback=["interface Ethernet0/2", " no ip access-group IBN_FIN_IN in",
                                               "no ip access-list extended IBN_FIN_IN"]))
    p1 = ibn.plan_submit([intent()], "a", a1)
    p2 = ibn.plan_submit([intent(description="no telnet", expectations=[])], "b", a2)
    ibn.deploy(p1.plan_id, dry_run=True, record_state=True)
    with pytest.raises(PlanError, match="state changed"):
        ibn.deploy(p2.plan_id, dry_run=True)


def test_failed_device_triggers_reverse_rollback(ibn):
    r3 = ["ip access-list extended IBN_FIN_IN", " deny tcp 10.0.3.0 0.0.0.255 10.0.1.0 0.0.0.255 eq 22",
          " permit ip any any", "interface Ethernet0/2", " ip access-group IBN_FIN_IN in"]
    both = design()
    both["devices"].append({**both["devices"][0], "device": "R3", "commands": r3,
                            "rollback": ["interface Ethernet0/2", " no ip access-group IBN_FIN_IN in",
                                         "no ip access-list extended IBN_FIN_IN"]})
    agent, _ = agent_for(ibn.kb, both)
    plan = ibn.plan_submit([intent()], "x", agent)
    assert plan.ok, plan.validation.to_markdown()
    deployer = ibn._deployer()
    deployer.connector = lambda kb, dev, dry: FailingConnection(kb.devices[dev], kb)
    rep = deployer.deploy(plan.plan_id, ibn.ordered(plan.design.devices), [Probe(**p) for p in plan.probes], dry_run=True)
    assert not rep.success and rep.rolled_back
    assert [d.status for d in rep.devices] == ["rolled_back", "rolled_back"]


def test_rollback_restores_previous_state(ibn):
    agent, _ = agent_for(ibn.kb, design())
    before = ibn.configs()
    plan = ibn.plan_submit([intent()], "x", agent)
    ibn.deploy(plan.plan_id, dry_run=True, record_state=True)
    rep = ibn.rollback(plan.plan_id, dry_run=True, record_state=True)
    assert rep.success and ibn.store.active() == [] and ibn.configs() == before


def test_invalid_intent_stops_before_design(ibn):
    agent, llm = agent_for(ibn.kb)
    plan = ibn.plan_submit([intent(scope={"groups": ["Nope"]})], "x", agent)
    assert not plan.ok and plan.design is None and llm.prompts == []
