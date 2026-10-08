"""Vendor-neutral configuration model (output of the Config Generator, input to drivers).

The generator always produces the full *managed* desired state of a device
(`DeviceState`). Drivers turn a before/after pair into device commands, so the
rollback for any change is simply the transition after -> before.
"""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field

from ibn.models.intent import Action, Protocol, SolutionKind


class PolicyRule(BaseModel):
    action: Action
    protocol: Protocol
    src: str  # CIDR
    dst: str  # CIDR
    ports: list[int] = Field(default_factory=list)  # destination ports
    intent_id: str | None = None

    def matches(self, src_ip: str, dst_ip: str, protocol: Protocol, port: int | None) -> bool:
        if ipaddress.IPv4Address(src_ip) not in ipaddress.IPv4Network(self.src):
            return False
        if ipaddress.IPv4Address(dst_ip) not in ipaddress.IPv4Network(self.dst):
            return False
        if self.protocol != Protocol.IP and self.protocol != protocol:
            return False
        if self.ports and port not in self.ports:
            return False
        return True


class AccessList(BaseModel):
    name: str
    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: Action = Action.PERMIT


class AclBinding(BaseModel):
    interface: str
    direction: Literal["in", "out"]
    acl: str


class ZonePair(BaseModel):
    name: str
    src_zone: str
    dst_zone: str
    policy: str  # versioned policy name; unmatched traffic is passed
    rules: list[PolicyRule] = Field(default_factory=list)  # deny -> drop, permit -> inspect


class FirewallConfig(BaseModel):
    zones: dict[str, str] = Field(default_factory=dict)  # interface -> zone
    zone_pairs: list[ZonePair] = Field(default_factory=list)


class Vlan(BaseModel):
    id: int
    name: str


class AccessPort(BaseModel):
    interface: str
    vlan: int


class DeviceState(BaseModel):
    """Everything IBN manages on one device. Unmanaged config is never touched."""

    revision: int = 0
    acls: list[AccessList] = Field(default_factory=list)
    bindings: list[AclBinding] = Field(default_factory=list)
    firewall: FirewallConfig | None = None
    vlans: list[Vlan] = Field(default_factory=list)
    access_ports: list[AccessPort] = Field(default_factory=list)

    def acl(self, name: str) -> AccessList | None:
        return next((a for a in self.acls if a.name == name), None)

    def binding(self, interface: str, direction: str) -> AclBinding | None:
        return next((b for b in self.bindings if b.interface == interface and b.direction == direction), None)

    def content_equal(self, other: "DeviceState") -> bool:
        return self.model_dump(exclude={"revision"}) == other.model_dump(exclude={"revision"})


class DeviceChange(BaseModel):
    device: str
    platform: str
    before: DeviceState
    after: DeviceState
    commands: list[str] = Field(default_factory=list)
    rollback: list[str] = Field(default_factory=list)


class CandidateConfig(BaseModel):
    solution: SolutionKind | None
    changes: list[DeviceChange] = Field(default_factory=list)

    def change(self, device: str) -> DeviceChange | None:
        return next((c for c in self.changes if c.device == device), None)
