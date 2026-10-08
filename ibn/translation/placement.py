"""Where in the topology an intent's rules are enforced."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.intent import Intent
from ibn.models.netconfig import PolicyRule

CORE_ZONE = "IBN_CORE"


@dataclass(frozen=True)
class AclPlacement:
    device: str
    interface: str
    direction: str  # "in" | "out"


@dataclass(frozen=True)
class FirewallPlacement:
    device: str
    src_zone: str
    dst_zone: str


def directional_rules(intent: Intent, kb: KnowledgeBase) -> list[PolicyRule]:
    src, dst = kb.resolve(intent.source), kb.resolve(intent.destination)
    pairs = [(src, dst)] + ([(dst, src)] if intent.bidirectional else [])
    return [PolicyRule(action=intent.action, protocol=svc.protocol, src=str(a), dst=str(b),
                       ports=list(svc.ports), intent_id=intent.id)
            for a, b in pairs for svc in intent.services]


def same_segment(kb: KnowledgeBase, rule: PolicyRule) -> bool:
    """Both ends on one L2 segment: the traffic never reaches a router."""
    src = kb.locate(ipaddress.IPv4Network(rule.src))
    return src is not None and src == kb.locate(ipaddress.IPv4Network(rule.dst))


def acl_placement(kb: KnowledgeBase, rule: PolicyRule) -> AclPlacement | None:
    """Extended ACL as close to the source as possible (inbound), else outbound towards the destination."""
    if same_segment(kb, rule):
        return None
    if loc := kb.locate(ipaddress.IPv4Network(rule.src)):
        return AclPlacement(loc[0], loc[1], "in")
    if loc := kb.locate(ipaddress.IPv4Network(rule.dst)):
        return AclPlacement(loc[0], loc[1], "out")
    return None


def zone_of(kb: KnowledgeBase, device: str, interface: str) -> str:
    group = kb.group_at(device, interface)
    return f"IBN_{group.name.upper()}" if group else CORE_ZONE


def device_zones(kb: KnowledgeBase, device: str) -> dict[str, str]:
    """Every routed interface must be in a zone once ZBF is enabled on a router."""
    return {i.name: zone_of(kb, device, i.name) for i in kb.l3_interfaces(device)}


def firewall_placement(kb: KnowledgeBase, rule: PolicyRule) -> FirewallPlacement | None:
    if same_segment(kb, rule):
        return None
    src_loc = kb.locate(ipaddress.IPv4Network(rule.src))
    dst_loc = kb.locate(ipaddress.IPv4Network(rule.dst))
    device = (src_loc or dst_loc or (None,))[0]
    if device is None:
        return None
    src_zone = zone_of(kb, *src_loc) if src_loc and src_loc[0] == device else CORE_ZONE
    dst_zone = zone_of(kb, *dst_loc) if dst_loc and dst_loc[0] == device else CORE_ZONE
    if src_zone == dst_zone:
        return None
    return FirewallPlacement(device, src_zone, dst_zone)
