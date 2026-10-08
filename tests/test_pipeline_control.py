import pytest

from ibn.control.connection import DryRunConnection
from ibn.pipeline import PlanError
from tests.conftest import intent


class FailingConnection(DryRunConnection):
    """Rejects config on one device, to exercise staged rollback."""

    fail_on = "R3"

    def send_config(self, commands):
        super().send_config(commands)
        return "% Invalid input detected at '^' marker." if self.name == self.fail_on and not \
            any(c.startswith("no ") or c.startswith(" no ") for c in commands) else ""


def test_submit_deploy_withdraw_roundtrip(ibn):
    plan = ibn.plan_submit([intent()], "deny HR->Finance")
    assert plan.ok and plan.chosen.value == "acl"
    assert (ibn.package_dir(plan.plan_id) / "configs" / "R1.txt").is_file()
    rep = ibn.deploy(plan.plan_id, dry_run=True, record_state=True)
    assert rep.success and rep.devices[0].backup
    assert [r.intent.id for r in ibn.store.active()] == [plan.intents[0].id]

    withdraw = ibn.plan_withdraw(plan.intents[0].id)
    assert withdraw.ok
    assert "no ip access-list extended IBN_E0_2_IN_R1" in withdraw.candidate.change("R1").commands
    ibn.deploy(withdraw.plan_id, dry_run=True, record_state=True)
    assert ibn.store.active() == []


def test_dry_run_without_record_does_not_change_state(ibn):
    plan = ibn.plan_submit([intent()], "x")
    ibn.deploy(plan.plan_id, dry_run=True)
    assert ibn.store.active() == []


def test_stale_plan_is_refused(ibn):
    p1 = ibn.plan_submit([intent()], "a")
    p2 = ibn.plan_submit([intent(src={"group": "Finance"}, dst={"group": "HR"},
                                 services=[{"protocol": "tcp", "ports": [22]}])], "b")
    ibn.deploy(p1.plan_id, dry_run=True, record_state=True)
    with pytest.raises(PlanError, match="state changed"):
        ibn.deploy(p2.plan_id, dry_run=True)


def test_failed_device_triggers_reverse_rollback(ibn):
    plan = ibn.plan_submit([intent(bidirectional=True)], "isolate")
    assert [c.device for c in plan.candidate.changes] == ["R1", "R3"]
    deployer = ibn._deployer()
    deployer.connector = lambda kb, dev, dry: FailingConnection(kb.devices[dev], kb)
    from ibn.control.verifier import Probe
    rep = deployer.deploy(plan.plan_id, plan.candidate, [Probe(**p) for p in plan.probes], dry_run=True)
    assert not rep.success and rep.rolled_back
    assert [d.status for d in rep.devices] == ["rolled_back", "rolled_back"]
    assert "rejected commands" in rep.messages[0]


def test_rollback_restores_previous_state(ibn):
    plan = ibn.plan_submit([intent()], "x")
    ibn.deploy(plan.plan_id, dry_run=True, record_state=True)
    rep = ibn.rollback(plan.plan_id, dry_run=True, record_state=True)
    assert rep.success
    assert ibn.store.active() == [] and ibn.store.managed() == {}


def test_invalid_intent_produces_no_candidate(ibn):
    plan = ibn.plan_submit([intent(dst={"group": "Nope"})], "x")
    assert not plan.ok and plan.candidate is None
