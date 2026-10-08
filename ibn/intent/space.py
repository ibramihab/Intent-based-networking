"""Traffic spaces: the set of flows an intent talks about. Used for conflicts and impact analysis."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.intent import Intent, Protocol


@dataclass(frozen=True)
class TrafficSpace:
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    protocol: Protocol
    ports: frozenset[int]

    def overlaps(self, other: "TrafficSpace") -> bool:
        if not (self.src.overlaps(other.src) and self.dst.overlaps(other.dst)):
            return False
        if Protocol.IP in (self.protocol, other.protocol):
            return True
        if self.protocol != other.protocol:
            return False
        return not self.ports or not other.ports or bool(self.ports & other.ports)

    def contains(self, other: "TrafficSpace") -> bool:
        if not (other.src.subnet_of(self.src) and other.dst.subnet_of(self.dst)):
            return False
        if self.protocol != Protocol.IP and self.protocol != other.protocol:
            return False
        return not self.ports or (bool(other.ports) and other.ports <= self.ports)

    def matches(self, src_ip: str, dst_ip: str, protocol: Protocol, port: int | None) -> bool:
        if ipaddress.IPv4Address(src_ip) not in self.src or ipaddress.IPv4Address(dst_ip) not in self.dst:
            return False
        if self.protocol != Protocol.IP and self.protocol != protocol:
            return False
        return not self.ports or port in self.ports


def spaces(intent: Intent, kb: KnowledgeBase) -> list[TrafficSpace]:
    src, dst = kb.resolve(intent.source), kb.resolve(intent.destination)
    out = []
    for svc in intent.services:
        out.append(TrafficSpace(src, dst, svc.protocol, frozenset(svc.ports)))
        if intent.bidirectional:
            out.append(TrafficSpace(dst, src, svc.protocol, frozenset(svc.ports)))
    return out


def specificity(space: TrafficSpace) -> tuple[int, int, int, int]:
    """Higher = more specific. Used for rule ordering and conflict resolution alike."""
    return (len(space.ports) > 0, space.protocol != Protocol.IP, space.src.prefixlen + space.dst.prefixlen,
            -len(space.ports))
