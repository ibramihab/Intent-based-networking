"""Platform contract. One module per vendor/OS gives the generic validator and control layer what
they need: syntax checking, config parsing into the vendor-neutral data-plane model, reference
tracking, and the few device commands the control layer runs itself."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ibn.models.dataplane import DeviceModel
from ibn.models.report import Issue
from ibn.platforms.configtree import ConfigTree


@dataclass(frozen=True)
class Ref:
    kind: str  # acl | class-map | policy-map | zone | route-map | prefix-list | object-group | interface | ...
    name: str
    where: str = ""


class Platform(ABC):
    name: str
    netmiko_device_type: str
    error_patterns: tuple[str, ...] = ()
    read_only_prefixes: tuple[str, ...] = ("show ", "ping ", "traceroute ")

    # ---------------------------------------------------------------- config text
    def parse(self, text: str) -> ConfigTree:
        return ConfigTree.parse(text)

    def normalize(self, commands: list[str]) -> list[str]:
        """Canonical spelling (e.g. expand interface abbreviations) before applying to a tree."""
        return commands

    def apply(self, tree: ConfigTree, commands: list[str]) -> ConfigTree:
        out = tree.copy()
        out.apply(self.normalize(commands))
        return out

    @abstractmethod
    def baseline_config(self, kb, device: str) -> str:
        """Config rendered from the knowledge base when no running config has been synced."""

    # ---------------------------------------------------------------- validation
    @abstractmethod
    def syntax_check(self, commands: list[str]) -> list[Issue]: ...

    @abstractmethod
    def dataplane(self, tree: ConfigTree, device: str) -> DeviceModel: ...

    @abstractmethod
    def references(self, tree: ConfigTree) -> tuple[set[tuple[str, str]], list[Ref]]:
        """(defined objects as (kind, name), references to objects)."""

    @abstractmethod
    def unmodeled(self, commands: list[str]) -> list[str]:
        """Human-readable list of features in `commands` the data-plane simulator cannot represent."""

    @abstractmethod
    def interface_commands(self, tree: ConfigTree) -> dict[str, list[str]]:
        """interface name -> its sub-commands."""

    # ---------------------------------------------------------------- control
    def netmiko_type(self, transport: str) -> str:
        return self.netmiko_device_type + ("_telnet" if transport == "telnet" else "")

    def command_errors(self, output: str) -> list[str]:
        return [ln.strip() for ln in output.splitlines() if any(p in ln for p in self.error_patterns)]

    def is_read_only(self, command: str) -> bool:
        s = command.strip()
        return s.startswith(self.read_only_prefixes) and not re.search(r"[;\n>]|\|\s*(redirect|tee|append)\b", s)

    @abstractmethod
    def ping_command(self, target: str, source_interface: str | None) -> str: ...

    @abstractmethod
    def ping_succeeded(self, output: str) -> bool: ...
