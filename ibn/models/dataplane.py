"""Vendor-neutral data-plane model extracted from device configuration by a platform parser.

The simulator only understands this model, so any vendor whose platform module can fill it
gets intent-compliance and impact simulation for free.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

EPHEMERAL_PORT = 50000


@dataclass
class PortMatch:
    op: str  # eq | neq | gt | lt | range
    values: list[int]

    def matches(self, port: int | None) -> bool:
        if port is None:
            return False
        if self.op == "eq":
            return port in self.values
        if self.op == "neq":
            return port not in self.values
        if self.op == "gt":
            return port > self.values[0]
        if self.op == "lt":
            return port < self.values[0]
        return self.values[0] <= port <= self.values[1]


@dataclass
class Ace:
    action: str  # permit | deny
    protocol: str  # ip | icmp | tcp | udp | other protocol name/number
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    src_port: PortMatch | None = None
    dst_port: PortMatch | None = None
    established: bool = False
    text: str = ""

    def matches(self, flow) -> bool:
        if self.protocol != "ip" and self.protocol != flow.protocol:
            return False
        if ipaddress.IPv4Address(flow.src) not in self.src or ipaddress.IPv4Address(flow.dst) not in self.dst:
            return False
        if self.established:  # only matches return traffic; simulated flows are connection openers
            return False
        if self.src_port and not self.src_port.matches(EPHEMERAL_PORT):
            return False
        if self.dst_port and not self.dst_port.matches(flow.port):
            return False
        return True


@dataclass
class Acl:
    name: str
    entries: list[Ace] = field(default_factory=list)

    def evaluate(self, flow) -> tuple[bool, str]:
        for ace in self.entries:
            if ace.matches(flow):
                return ace.action == "permit", f"{self.name}: '{ace.text}'"
        return False, f"{self.name}: implicit deny"


@dataclass
class InterfaceState:
    name: str
    ip: ipaddress.IPv4Interface | None = None
    shutdown: bool = False
    acl_in: str | None = None
    acl_out: str | None = None
    zone: str | None = None
    access_vlan: int = 1

    @property
    def up(self) -> bool:
        return not self.shutdown


@dataclass
class ClassMap:
    name: str
    match_all: bool = False
    acls: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class InspectPolicy:
    name: str
    rules: list[tuple[str, str]] = field(default_factory=list)  # (class name, inspect|pass|drop)
    default_action: str = "drop"


@dataclass
class ZonePair:
    name: str
    src: str
    dst: str
    policy: str | None = None


@dataclass
class DeviceModel:
    name: str
    interfaces: dict[str, InterfaceState] = field(default_factory=dict)
    acls: dict[str, Acl] = field(default_factory=dict)
    class_maps: dict[str, ClassMap] = field(default_factory=dict)
    policies: dict[str, InspectPolicy] = field(default_factory=dict)
    zone_pairs: list[ZonePair] = field(default_factory=list)
    null_routes: list[ipaddress.IPv4Network] = field(default_factory=list)
    vlans: set[int] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)  # parts of the config the model could not represent

    def l3_interfaces(self) -> list[InterfaceState]:
        return [i for i in self.interfaces.values() if i.ip and i.up]


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    protocol: str  # icmp | tcp | udp
    port: int | None = None

    def __str__(self) -> str:
        return f"{self.src} -> {self.dst} {self.protocol}{'/' + str(self.port) if self.port else ''}"
