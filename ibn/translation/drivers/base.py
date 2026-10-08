"""Vendor driver contract. Implement this once per platform (cisco_ios, juniper_junos, arista_eos …)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ibn.models.netconfig import DeviceState
from ibn.models.report import Issue


@dataclass
class Check:
    """A show command and the strings its output must / must not contain."""

    command: str
    must_contain: list[str] = field(default_factory=list)
    must_not_contain: list[str] = field(default_factory=list)

    def evaluate(self, output: str) -> list[str]:
        problems = [f"'{s}' missing from '{self.command}'" for s in self.must_contain if s not in output]
        problems += [f"'{s}' still present in '{self.command}'" for s in self.must_not_contain if s in output]
        return problems


class VendorDriver(ABC):
    platform: str
    netmiko_device_type: str
    error_patterns: tuple[str, ...] = ()

    @abstractmethod
    def render_transition(self, before: DeviceState, after: DeviceState) -> list[str]:
        """Commands that move the managed config from `before` to `after` (also used for rollback)."""

    @abstractmethod
    def validate_syntax(self, commands: list[str]) -> list[Issue]:
        """Offline syntax check of rendered commands."""

    @abstractmethod
    def verification_checks(self, before: DeviceState, after: DeviceState) -> list[Check]:
        """Post-deployment checks proving the running config matches `after`."""

    @abstractmethod
    def ping_command(self, target: str, source_interface: str | None) -> str: ...

    @abstractmethod
    def ping_succeeded(self, output: str) -> bool: ...

    def netmiko_type(self, transport: str) -> str:
        return self.netmiko_device_type + ("_telnet" if transport == "telnet" else "")

    def command_errors(self, output: str) -> list[str]:
        return [ln.strip() for ln in output.splitlines() if any(p in ln for p in self.error_patterns)]
