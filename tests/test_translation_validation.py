import ipaddress

from ibn.intent.validation import validate_intents
from ibn.kb.knowledge_base import Host
from ibn.models.intent import Protocol, SolutionKind
from ibn.models.report import Severity
from ibn.translation.drivers import get_driver
from ibn.translation.generator import build_candidate
from ibn.translation.selector import rank
from ibn.validation.simulator import Flow, Simulator
from ibn.validation.validator import Validator
from tests.conftest import intent

IOS = get_driver("cisco_ios")


def _intents(kb, *raw):
    intents, report = validate_intents(list(raw), kb, [])
    assert report.passed, report.to_markdown()
    return intents


def _candidate(kb, intents, kind, current=None):
    return build_candidate(kb, [(i, kind) for i in intents], current or {}, kind)


def test_selector_prefers_acl_for_deny_and_rejects_vlan_for_routed_groups(kb):
    opts = rank(_intents(kb, intent()), kb)
    assert opts[0].kind == SolutionKind.ACL
    vlan = next(o for o in opts if o.kind == SolutionKind.VLAN)
    assert not vlan.feasible and "routed subnets" in vlan.reasons[0]


def test_operator_preference_wins(kb):
    opts = rank(_intents(kb, intent(preferred_solution="firewall")), kb)
    assert opts[0].kind == SolutionKind.FIREWALL


def test_acl_rendering_order_and_rollback(kb):
    intents = _intents(kb, intent("permit", services=[{"protocol": "tcp", "ports": [443]}]), intent("deny"))
    ch = _candidate(kb, intents, SolutionKind.ACL).change("R1")
    body = [c for c in ch.commands if c.lstrip()[:2].isdigit()]
    assert body == [" 10 permit tcp 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255 eq 443",
                    " 20 deny ip 10.0.1.0 0.0.0.255 10.0.3.0 0.0.0.255",
                    " 30 permit ip any any"]
    assert "interface Ethernet0/2" in ch.commands and " ip access-group IBN_E0_2_IN_R1 in" in ch.commands
    assert ch.rollback == ["interface Ethernet0/2", " no ip access-group IBN_E0_2_IN_R1 in",
                           "no ip access-list extended IBN_E0_2_IN_R1"]
    assert IOS.validate_syntax(ch.commands + ch.rollback) == []


def test_acl_update_is_hitless_swap(kb):
    first = _intents(kb, intent(services=[{"protocol": "tcp", "ports": [80]}]))
    c1 = _candidate(kb, first, SolutionKind.ACL)
    current = {c.device: c.after for c in c1.changes}
    second = _intents(kb, intent(services=[{"protocol": "tcp", "ports": [22]}]))
    c2 = build_candidate(kb, [(first[0], SolutionKind.ACL), (second[0], SolutionKind.ACL)], current, SolutionKind.ACL)
    cmds = c2.change("R1").commands
    assert cmds[0] == "ip access-list extended IBN_E0_2_IN_R2"
    assert cmds.index(" ip access-group IBN_E0_2_IN_R2 in") < cmds.index("no ip access-list extended IBN_E0_2_IN_R1")


def test_firewall_zones_cover_all_routed_interfaces(kb):
    ch = _candidate(kb, _intents(kb, intent(bidirectional=True)), SolutionKind.FIREWALL)
    r1 = ch.change("R1").after.firewall
    assert r1.zones == {"Ethernet0/0": "IBN_CORE", "Ethernet0/2": "IBN_HR", "Tunnel0": "IBN_CORE"}
    assert {z.name for z in r1.zone_pairs} == {"IBN_ZP_HR_CORE", "IBN_ZP_CORE_HR"}
    cmds = ch.change("R1").commands
    assert cmds.index(" zone-member security IBN_HR") > cmds.index(" service-policy type inspect IBN_PM_HR_CORE_R1")
    assert IOS.validate_syntax(cmds + ch.change("R1").rollback) == []


def test_vlan_isolation_on_shared_switch(kb):
    kb.hosts["VPC6"] = Host("VPC6", ipaddress.IPv4Address("10.0.1.11"), "HR", "SW1", "Ethernet0/1")
    kb.interfaces["SW1"]["Ethernet0/1"] = type(kb.interfaces["SW1"]["Ethernet0/0"])("SW1", "Ethernet0/1", vlan=1)
    intents = _intents(kb, intent(src={"host": "VPC4"}, dst={"host": "VPC6"}))
    assert rank(intents, kb)[0].kind == SolutionKind.VLAN
    ch = _candidate(kb, intents, SolutionKind.VLAN).change("SW1")
    assert ch.commands[:2] == ["vlan 100", " name IBN_ISOLATE_VPC4"]
    assert " switchport access vlan 1" in ch.rollback and "no vlan 100" in ch.rollback
    sim = Simulator(kb, {"SW1": ch.after})
    assert not sim.evaluate(Flow("10.0.1.10", "10.0.1.11", Protocol.ICMP)).allowed


def test_syntax_validator_catches_bad_commands():
    issues = IOS.validate_syntax([" 10 deny ip 10.0.1.0 0.0.255.0 any", "ip acces-list extended X",
                                  " 20 deny icmp any any eq 80"])
    msgs = " ".join(i.message for i in issues)
    assert "wildcard" in msgs and "unrecognised" in msgs and "requires tcp/udp" in msgs


def test_simulator_uses_tunnel_and_enforces_acl(kb):
    ch = _candidate(kb, _intents(kb, intent(services=[{"protocol": "tcp", "ports": [80]}])), SolutionKind.ACL)
    sim = Simulator(kb, {c.device: c.after for c in ch.changes})
    denied = sim.evaluate(Flow("10.0.1.10", "10.0.3.10", Protocol.TCP, 80))
    assert not denied.allowed and "out=Tunnel0" in denied.trace[0]
    assert sim.evaluate(Flow("10.0.1.10", "10.0.3.10", Protocol.TCP, 443)).allowed
    assert sim.evaluate(Flow("10.0.3.10", "10.0.1.10", Protocol.TCP, 80)).allowed


def test_validator_passes_and_reports_impact(kb):
    intents = _intents(kb, intent())
    cand = _candidate(kb, intents, SolutionKind.ACL)
    report = Validator(kb).validate(cand, {}, intents, intents, "t")
    assert report.passed, report.to_markdown()
    impact = next(s for s in report.stages if s.name == "Impact analysis")
    assert impact.details["changed_flows"] and all(d["explained"] for d in impact.details["changed_flows"])


def test_guardrail_blocks_infrastructure_intent(kb):
    raw = intent(src={"subnet": "10.1.2.0/24"}, dst={"subnet": "10.2.3.0/24"})
    _, report = validate_intents([raw], kb, [])
    assert any("guardrail" in e.message for e in report.errors())


def test_impact_flags_collateral_and_protected_changes(kb):
    # an ACL that the intent model does not explain (simulates a buggy generator)
    intents = _intents(kb, intent())
    cand = _candidate(kb, intents, SolutionKind.ACL)
    cand.change("R1").after.acls[0].rules[0].dst = "0.0.0.0/0"
    report = Validator(kb).validate(cand, {}, intents, intents, "t")
    impact = next(s for s in report.stages if s.name == "Impact analysis")
    assert any(i.severity == Severity.WARNING and "collateral" in i.message for i in impact.issues)


def test_semantic_detects_unmanaged_acl_on_interface(kb):
    (kb.path / "configs" / "R1.cfg").write_text("interface Ethernet0/2\n ip access-group LEGACY in\n!\n")
    intents = _intents(kb, intent())
    report = Validator(kb).validate(_candidate(kb, intents, SolutionKind.ACL), {}, intents, intents, "t")
    assert any("unmanaged ACL LEGACY" in e.message for e in report.errors())
    assert any(i.severity == Severity.INFO for s in report.stages for i in s.issues)
