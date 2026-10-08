"""Generic, vendor-neutral intent (output of the Intent Layer's understanding step).

An intent says WHAT the operator wants, never HOW. Its `expectations` are concrete traffic tests
that the Validation Layer simulates and the Control Layer checks after deployment, whatever
technique the AI later chooses to implement it.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Expectation(BaseModel):
    """A traffic test: traffic from src to dst must be allowed or denied."""

    model_config = ConfigDict(extra="ignore")

    src: str = Field(description="host, group, device, IP address or CIDR")
    dst: str
    protocol: Literal["any", "icmp", "tcp", "udp"] = "any"
    port: int | None = Field(None, ge=1, le=65535, description="destination port (tcp/udp only)")
    expect: Literal["allow", "deny"]

    @model_validator(mode="after")
    def _port_needs_l4(self) -> "Expectation":
        if self.port is not None and self.protocol not in ("tcp", "udp"):
            raise ValueError(f"port is only valid for tcp/udp, not {self.protocol}")
        return self

    @property
    def label(self) -> str:
        svc = self.protocol + (f"/{self.port}" if self.port else "")
        return f"{self.src} -> {self.dst} {svc}: {self.expect}"


class Scope(BaseModel):
    model_config = ConfigDict(extra="ignore")

    groups: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    devices: list[str] = Field(default_factory=list)
    subnets: list[str] = Field(default_factory=list)

    @field_validator("subnets")
    @classmethod
    def _cidrs(cls, subnets: list[str]) -> list[str]:
        for s in subnets:
            try:
                ipaddress.IPv4Network(s, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid subnet {s!r}") from exc
        return subnets


class Intent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: f"int-{uuid4().hex[:8]}")
    description: str = Field(min_length=3)
    category: str = "other"
    requirements: list[str] = Field(default_factory=list)
    scope: Scope = Field(default_factory=Scope)
    expectations: list[Expectation] = Field(default_factory=list)
    priority: int = Field(100, ge=1, le=1000, description="higher wins when intents overlap")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def summary(self) -> str:
        return f"[{self.category}] {self.description} (prio {self.priority})"
