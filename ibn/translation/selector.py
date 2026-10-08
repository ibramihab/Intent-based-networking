"""Solution Selector: score ACL, firewall and VLAN options and record why one was chosen."""

from __future__ import annotations

from dataclasses import dataclass, field

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.intent import Action, Intent, Protocol, SolutionKind
from ibn.translation.placement import acl_placement, directional_rules, firewall_placement, same_segment

DEFAULT_WEIGHTS = {SolutionKind.ACL: 70, SolutionKind.FIREWALL: 55, SolutionKind.VLAN: 60}


@dataclass
class SolutionOption:
    kind: SolutionKind
    feasible: bool
    score: float
    reasons: list[str] = field(default_factory=list)


def _base(kb: KnowledgeBase, kind: SolutionKind) -> int:
    return int(kb.policies.solution_weights.get(kind.value, DEFAULT_WEIGHTS[kind]))


def _score_acl(it: Intent, kb: KnowledgeBase) -> SolutionOption:
    opt = SolutionOption(SolutionKind.ACL, True, _base(kb, SolutionKind.ACL))
    places = []
    for rule in directional_rules(it, kb):
        if same_segment(kb, rule):
            return SolutionOption(SolutionKind.ACL, False, 0, [f"{rule.src} and {rule.dst} share one L2 segment; "
                                                               "the traffic never crosses a router"])
        p = acl_placement(kb, rule)
        if p is None:
            return SolutionOption(SolutionKind.ACL, False, 0, [f"no router interface is attached to {rule.src} or {rule.dst}"])
        if "acl" not in kb.devices[p.device].capabilities:
            return SolutionOption(SolutionKind.ACL, False, 0, [f"{p.device} does not support ACLs"])
        places.append(f"{p.device} {p.interface} {p.direction}")
    opt.reasons.append(f"extended ACL at {', '.join(sorted(set(places)))} (closest to the source)")
    if it.action == Action.DENY:
        opt.score += 15
        opt.reasons.append("+15 stateless deny is exactly what an ACL does best")
    elif any(s.ports for s in it.services):
        opt.score -= 5
        opt.reasons.append("-5 stateless: return traffic is not tracked")
    opt.score += 10
    opt.reasons.append("+10 low blast radius: only the bound interface is touched, default-permit kept")
    return opt


def _score_firewall(it: Intent, kb: KnowledgeBase) -> SolutionOption:
    opt = SolutionOption(SolutionKind.FIREWALL, True, _base(kb, SolutionKind.FIREWALL))
    places = []
    for rule in directional_rules(it, kb):
        if same_segment(kb, rule):
            return SolutionOption(SolutionKind.FIREWALL, False, 0, [f"{rule.src} and {rule.dst} share one L2 segment; "
                                                                    "the traffic never crosses a router"])
        p = firewall_placement(kb, rule)
        if p is None:
            return SolutionOption(SolutionKind.FIREWALL, False, 0, [f"no zone boundary separates {rule.src} and {rule.dst}"])
        if "zbf" not in kb.devices[p.device].capabilities:
            return SolutionOption(SolutionKind.FIREWALL, False, 0, [f"{p.device} does not support zone-based firewall"])
        places.append(f"{p.device} {p.src_zone}->{p.dst_zone}")
    opt.reasons.append(f"zone-based firewall at {', '.join(sorted(set(places)))}")
    if it.action == Action.PERMIT and any(s.protocol != Protocol.IP for s in it.services):
        opt.score += 20
        opt.reasons.append("+20 stateful inspection lets return traffic in automatically")
    opt.score -= 10
    opt.reasons.append("-10 every routed interface of the router must join a zone (higher blast radius)")
    return opt


def _score_vlan(it: Intent, kb: KnowledgeBase) -> SolutionOption:
    def no(reason: str) -> SolutionOption:
        return SolutionOption(SolutionKind.VLAN, False, 0, [reason])

    if it.action != Action.DENY or any(s.protocol != Protocol.IP for s in it.services):
        return no("VLANs can only isolate all traffic, not filter specific services or permit")
    if not (it.source.host and it.destination.host):
        return no(f"{it.source.label} and {it.destination.label} are routed subnets; L2 segmentation cannot separate them")
    a, b = kb.hosts[it.source.host], kb.hosts[it.destination.host]
    if a.switch != b.switch or a.group != b.group or not a.switch:
        return no(f"{a.name} and {b.name} are not on the same access switch/subnet")
    if "vlan" not in kb.devices[a.switch].capabilities:
        return no(f"{a.switch} does not support VLAN changes")
    return SolutionOption(SolutionKind.VLAN, True, _base(kb, SolutionKind.VLAN) + 20, [
        f"move {a.name} ({a.switch} {a.port}) into an isolated VLAN",
        "+20 complete L2 isolation without touching routers",
    ])


SCORERS = {SolutionKind.ACL: _score_acl, SolutionKind.FIREWALL: _score_firewall, SolutionKind.VLAN: _score_vlan}


def rank(intents: list[Intent], kb: KnowledgeBase) -> list[SolutionOption]:
    """Options feasible for every intent in the request, best first, then infeasible ones."""
    options = []
    for kind, scorer in SCORERS.items():
        per_intent = [scorer(it, kb) for it in intents]
        feasible = all(o.feasible for o in per_intent)
        score = sum(o.score for o in per_intent) / len(per_intent) if feasible else 0
        reasons = []
        for it, o in zip(intents, per_intent):
            prefix = f"{it.id}: " if len(intents) > 1 else ""
            reasons += [prefix + r for r in o.reasons]
            if feasible and it.preferred_solution == kind:
                score += 100 / len(intents)
                reasons.append(prefix + "+100 requested by the operator (wins whenever feasible)")
        options.append(SolutionOption(kind, feasible, round(score, 1), reasons))
    return sorted(options, key=lambda o: (not o.feasible, -o.score))
