"""Vendor-neutral, structured intent (output of the Intent Layer)."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Protocol(str, Enum):
    IP = "ip"  # any IP traffic
    ICMP = "icmp"
    TCP = "tcp"
    UDP = "udp"


class Action(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


class SolutionKind(str, Enum):
    ACL = "acl"
    FIREWALL = "firewall"  # Cisco: zone-based policy firewall
    VLAN = "vlan"


class Endpoint(BaseModel):
    """Exactly one of group (e.g. HR), host (e.g. VPC4) or subnet (CIDR)."""

    model_config = ConfigDict(extra="forbid")

    group: str | None = None
    host: str | None = None
    subnet: str | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> "Endpoint":
        given = [f for f in ("group", "host", "subnet") if getattr(self, f)]
        if len(given) != 1:
            raise ValueError("endpoint needs exactly one of: group, host, subnet")
        if self.subnet:
            try:
                ipaddress.IPv4Network(self.subnet, strict=True)
            except ValueError as exc:
                raise ValueError(f"invalid subnet {self.subnet!r}: {exc}") from exc
        return self

    @property
    def label(self) -> str:
        return self.group or self.host or self.subnet or "?"


class Service(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Protocol = Protocol.IP
    ports: list[int] = Field(default_factory=list, description="destination ports (tcp/udp only)")

    @field_validator("ports")
    @classmethod
    def _port_range(cls, ports: list[int]) -> list[int]:
        for p in ports:
            if not 1 <= p <= 65535:
                raise ValueError(f"port {p} out of range 1-65535")
        return sorted(set(ports))

    @model_validator(mode="after")
    def _ports_need_l4(self) -> "Service":
        if self.ports and self.protocol not in (Protocol.TCP, Protocol.UDP):
            raise ValueError(f"ports are only valid for tcp/udp, not {self.protocol.value}")
        return self

    @property
    def label(self) -> str:
        if self.ports:
            return f"{self.protocol.value}/{','.join(map(str, self.ports))}"
        return self.protocol.value


class Intent(BaseModel):
    """A traffic-policy intent. New intent types are added as new models + a `type` literal."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"int-{uuid4().hex[:8]}")
    type: Literal["traffic_policy"] = "traffic_policy"
    description: str
    action: Action
    source: Endpoint
    destination: Endpoint
    services: list[Service] = Field(default_factory=lambda: [Service()], min_length=1)
    bidirectional: bool = False
    priority: int = Field(100, ge=1, le=1000, description="higher wins on overlap")
    preferred_solution: SolutionKind | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def summary(self) -> str:
        arrow = "<->" if self.bidirectional else "->"
        svcs = " ".join(s.label for s in self.services)
        return f"{self.action.value.upper()} {self.source.label} {arrow} {self.destination.label} [{svcs}] (prio {self.priority})"
