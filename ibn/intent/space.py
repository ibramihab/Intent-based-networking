"""Expectation flow spaces: shared by conflict detection, intent compliance and impact analysis."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.dataplane import Flow
from ibn.models.intent import Expectation, Intent

ANY_SAMPLES = (("icmp", None), ("tcp", 443))  # what "all traffic" is tested with


@dataclass(frozen=True)
class FlowSpace:
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    protocol: str  # any | icmp | tcp | udp
    port: int | None
    allow: bool
    priority: int
    intent_id: str
    label: str

    def matches(self, flow: Flow) -> bool:
        return (ipaddress.IPv4Address(flow.src) in self.src and ipaddress.IPv4Address(flow.dst) in self.dst
                and self.protocol in ("any", flow.protocol) and self.port in (None, flow.port))

    def overlaps(self, other: "FlowSpace") -> bool:
        return (self.src.overlaps(other.src) and self.dst.overlaps(other.dst)
                and ("any" in (self.protocol, other.protocol) or self.protocol == other.protocol)
                and (self.port is None or other.port is None or self.port == other.port))

    def contains(self, other: "FlowSpace") -> bool:
        return (other.src.subnet_of(self.src) and other.dst.subnet_of(self.dst)
                and self.protocol in ("any", other.protocol) and self.port in (None, other.port))

    @property
    def specificity(self) -> tuple[int, int, int]:
        return (self.port is not None, self.protocol != "any", self.src.prefixlen + self.dst.prefixlen)

    @property
    def precedence(self) -> tuple:
        return (self.priority, self.specificity)


def space(exp: Expectation, intent: Intent, kb: KnowledgeBase) -> FlowSpace:
    return FlowSpace(kb.endpoint_net(exp.src), kb.endpoint_net(exp.dst), exp.protocol, exp.port,
                     exp.expect == "allow", intent.priority, intent.id, exp.label)


def spaces(intent: Intent, kb: KnowledgeBase) -> list[FlowSpace]:
    return [space(e, intent, kb) for e in intent.expectations]


def sample_flows(sp: FlowSpace, kb: KnowledgeBase) -> list[Flow]:
    src, dst = kb.representative_ip(sp.src), kb.representative_ip(sp.dst)
    if sp.protocol == "any":
        return [Flow(src, dst, p, port) for p, port in ANY_SAMPLES]
    if sp.protocol in ("tcp", "udp") and sp.port is None:
        return [Flow(src, dst, sp.protocol, 443 if sp.protocol == "tcp" else 53)]
    return [Flow(src, dst, sp.protocol, sp.port)]


def intended(flow: Flow, all_spaces: list[FlowSpace]) -> FlowSpace | None:
    """The expectation that governs a flow: highest priority, then most specific."""
    matching = [s for s in all_spaces if s.matches(flow)]
    return max(matching, key=lambda s: s.precedence) if matching else None
