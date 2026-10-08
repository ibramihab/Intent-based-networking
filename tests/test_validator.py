import pytest

from ibn.kb.state import StateStore
from ibn.models.design import ConfigDesign
from ibn.models.intent import Intent
from ibn.models.report import Severity
from ibn.validation.validator import ValidationContext, Validator
from tests.conftest import ACL_COMMANDS, design, intent


@pytest.fixture
def check(kb, root):
    configs = StateStore(root / "kb" / "state").configs(kb)

    def run(d, intents=None, reviewer=None):
        intents = intents if intents is not None else [Intent.model_validate(intent())]
        ctx = ValidationContext(configs, intents, intents, reviewer)
        return Validator(kb).validate(ConfigDesign.model_validate(d), ctx, "t")

    return run


def stage(result, name):
    return next(s for s in result.report.stages if s.name.startswith(name))


def msgs(result):
    return " ".join(str(i) for s in result.report.stages for i in s.issues)


def test_good_acl_design_passes_every_stage(check):
    res = check(design())
    assert res.report.passed, res.report.to_markdown()
    assert not res.limited
    assert stage(res, "Intent compliance").details["probes"]
    assert " ip access-group IBN_HR_IN in" in res.after["R1"]


def test_structure_and_syntax_errors(check):
    res = check(design(rollback=[], verify=[{"command": "clear counters"}]))
    text = msgs(res)
    assert "no rollback commands" in text and "not read-only" in text
    res = check(design(commands=ACL_COMMANDS + ["write memory", "username hacker privilege 15 secret x"]))
    text = msgs(res)
    assert "forbidden (exec commands" in text and "credential" in text
    res = check(design(device="R9"))
    assert "unknown device R9" in msgs(res)


def test_semantic_checks(check):
    res = check(design(commands=["interface Ethernet0/2", " ip access-group IBN_NOPE in", "interface Ethernet0/9",
                                 " ip address 10.0.3.1 255.255.255.0"],
                       rollback=["interface Ethernet0/2", " no ip access-group IBN_NOPE in", "no interface Ethernet0/9"]))
    text = msgs(res)
    assert "acl 'IBN_NOPE' is referenced" in text
    assert "interface Ethernet0/9 does not exist" in text
    assert "subnet 10.0.3.0/24 is used on both" in text


def test_protected_interface_shutdown_is_blocked(check):
    res = check(design(commands=["interface Ethernet0/0", " shutdown"], rollback=["interface Ethernet0/0", " no shutdown"]))
    assert "shuts down infrastructure interface Ethernet0/0" in msgs(res)
    assert not res.report.passed


def test_incomplete_rollback_is_rejected(check):
    res = check(design(rollback=["interface Ethernet0/2", " no ip access-group IBN_HR_IN in"]))
    assert "rollback does not restore" in str(stage(res, "Rollback").issues)


def test_compliance_catches_a_design_that_misses_the_intent(check):
    wrong = [c.replace("eq 22", "eq 23") for c in ACL_COMMANDS]
    res = check(design(commands=wrong))
    comp = stage(res, "Intent compliance")
    assert not comp.passed and "tcp/22 should be denied" in str(comp.issues)


def test_impact_flags_collateral_damage(check):
    too_broad = [c.replace("tcp 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255 eq 22", "ip 10.0.1.0 0.0.0.255 any")
                 for c in ACL_COMMANDS]
    only_ssh = Intent.model_validate(intent(expectations=[
        {"src": "HR", "dst": "Finance", "protocol": "tcp", "port": 22, "expect": "deny"}]))
    res = check(design(commands=too_broad), intents=[only_ssh])
    impact = stage(res, "Impact")
    assert any(i.severity == Severity.WARNING and "collateral" in i.message for i in impact.issues)


def test_zone_based_firewall_design_is_simulated(check):
    cmds = ["zone security IBN_HR", "zone security IBN_CORE",
            "ip access-list extended IBN_SSH", " permit tcp any any eq 22",
            "class-map type inspect match-any IBN_CM_SSH", " match access-group name IBN_SSH",
            "class-map type inspect match-any IBN_CM_ALL", " match protocol tcp", " match protocol udp", " match protocol icmp",
            "policy-map type inspect IBN_PM", " class type inspect IBN_CM_SSH", "  drop",
            " class type inspect IBN_CM_ALL", "  inspect", " class class-default", "  drop",
            "zone-pair security IBN_ZP_OUT source IBN_HR destination IBN_CORE", " service-policy type inspect IBN_PM",
            "policy-map type inspect IBN_PM_RET", " class type inspect IBN_CM_ALL", "  pass", " class class-default", "  drop",
            "zone-pair security IBN_ZP_IN source IBN_CORE destination IBN_HR", " service-policy type inspect IBN_PM_RET",
            "interface Ethernet0/2", " zone-member security IBN_HR", "interface Ethernet0/0", " zone-member security IBN_CORE",
            "interface Tunnel0", " zone-member security IBN_CORE"]
    rollback = ["interface Ethernet0/2", " no zone-member security IBN_HR", "interface Ethernet0/0",
                " no zone-member security IBN_CORE", "interface Tunnel0", " no zone-member security IBN_CORE",
                "no zone-pair security IBN_ZP_OUT", "no zone-pair security IBN_ZP_IN", "no policy-map type inspect IBN_PM",
                "no policy-map type inspect IBN_PM_RET", "no class-map type inspect match-any IBN_CM_SSH",
                "no class-map type inspect match-any IBN_CM_ALL", "no ip access-list extended IBN_SSH",
                "no zone security IBN_HR", "no zone security IBN_CORE"]
    res = check(design(commands=cmds, rollback=rollback, approach="zone-based firewall"))
    assert res.report.passed, res.report.to_markdown()


def test_unmodeled_technique_is_limited_not_blocked(check):
    route = Intent.model_validate(intent(description="Prefer R2", expectations=[
        {"src": "HR", "dst": "Finance", "protocol": "icmp", "expect": "allow"}]))
    res = check(design(commands=["ip route 10.0.3.0 255.255.255.0 10.1.2.2"],
                       rollback=["no ip route 10.0.3.0 255.255.255.0 10.1.2.2"], approach="static route"), [route])
    assert res.report.passed
    assert res.limited == ["R1: static route (path changes are not simulated)"]


def test_null_route_and_vlan_isolation_are_simulated(kb, check):
    block = Intent.model_validate(intent(expectations=[{"src": "HR", "dst": "VPC5", "expect": "deny"}]))
    res = check(design(commands=["ip route 10.0.3.10 255.255.255.255 Null0"],
                       rollback=["no ip route 10.0.3.10 255.255.255.255 Null0"]), [block])
    assert stage(res, "Intent compliance").passed
    isolate = Intent.model_validate(intent(expectations=[{"src": "VPC5", "dst": "HR", "expect": "deny"}]))
    res = check(design(device="SW3", commands=["vlan 150", " name IBN_ISOLATED", "interface Ethernet0/0",
                                               " switchport access vlan 150"],
                       rollback=["interface Ethernet0/0", " no switchport access vlan 150", "no vlan 150"]), [isolate])
    assert stage(res, "Intent compliance").passed, res.report.to_markdown()


def test_reviewer_errors_block(check):
    res = check(design(), reviewer=lambda d: {"verdict": "reject",
                                              "findings": [{"severity": "error", "message": "wrong interface"}]})
    assert not res.report.passed and "wrong interface" in msgs(res)
    res = check(design(), reviewer=lambda d: (_ for _ in ()).throw(RuntimeError("quota")))
    assert res.report.passed and "AI review failed: quota" in msgs(res)
