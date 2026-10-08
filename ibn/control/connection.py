"""Device connectivity. Netmiko covers SSH and telnet (EVE-NG console) for many vendors;
a NETCONF/RESTCONF or Nornir-based connection can be added by implementing `DeviceConnection`."""

from __future__ import annotations

import os
from typing import Protocol

from ibn.kb.knowledge_base import Device, KnowledgeBase
from ibn.platforms import get_platform


class ConnectionError_(Exception):
    pass


class DeviceConnection(Protocol):
    name: str

    def open(self) -> None: ...
    def close(self) -> None: ...
    def send_config(self, commands: list[str]) -> str: ...
    def send_command(self, command: str) -> str: ...
    def save(self) -> str: ...


class NetmikoConnection:
    def __init__(self, device: Device):
        self.name = device.name
        self.device = device
        self.driver = get_platform(device.platform)
        self._conn = None

    def _cred(self, key: str) -> str | None:
        env = self.device.credentials.get(f"{key}_env")
        return os.environ.get(env) if env else None

    def open(self) -> None:
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            raise ConnectionError_("netmiko is not installed (pip install netmiko)") from exc
        params = {
            "device_type": self.driver.netmiko_type(self.device.mgmt.transport),
            "host": self.device.mgmt.host,
            "port": self.device.mgmt.port,
            "username": self._cred("username") or "",
            "password": self._cred("password") or "",
            "secret": self._cred("secret") or "",
            "fast_cli": False,
        }
        try:
            self._conn = ConnectHandler(**params)
            if params["secret"]:
                self._conn.enable()
        except Exception as exc:
            raise ConnectionError_(f"{self.name}: cannot connect to {params['host']}:{params['port']} "
                                   f"via {self.device.mgmt.transport}: {exc}") from exc

    def close(self) -> None:
        if self._conn:
            self._conn.disconnect()
            self._conn = None

    def send_config(self, commands: list[str]) -> str:
        return self._conn.send_config_set(commands, cmd_verify=False)

    def send_command(self, command: str) -> str:
        return self._conn.send_command(command, read_timeout=30)

    def save(self) -> str:
        return self._conn.save_config()


class DryRunConnection:
    """Talks to nothing. Records commands so the whole control flow can be exercised offline."""

    def __init__(self, device: Device, kb: KnowledgeBase):
        self.name = device.name
        self.kb = kb
        self.sent: list[str] = []

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def send_config(self, commands: list[str]) -> str:
        self.sent += commands
        return ""

    def send_command(self, command: str) -> str:
        if command == "show running-config":
            return self.kb.running_config(self.name) or "! dry-run: no synced running config\n"
        return ""

    def save(self) -> str:
        return ""


def connect(kb: KnowledgeBase, device: str, dry_run: bool) -> DeviceConnection:
    dev = kb.devices[device]
    return DryRunConnection(dev, kb) if dry_run else NetmikoConnection(dev)
