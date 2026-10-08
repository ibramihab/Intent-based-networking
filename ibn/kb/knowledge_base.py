"""Shared Network Knowledge Base: inventory, topology, policies and synced running configs."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ibn.models.intent import Endpoint, Protocol, Service
from ibn.models.report import Issue, error, warning

IPv4Net = ipaddress.IPv4Network


class KBError(Exception):
    pass


@dataclass(frozen=True)
class Mgmt:
    host: str
    port: int = 22
    transport: str = "ssh"


@dataclass
class Device:
    name: str
    role: str
    vendor: str
    platform: str
    os_version: str
    capabilities: frozenset[str]
    mgmt: Mgmt
    credentials: dict[str, str]


@dataclass
class Interface:
    device: str
    name: str
    ip: ipaddress.IPv4Interface | None = None
    description: str = ""
    mode: str | None = None
    vlan: int | None = None
    tunnel: dict[str, Any] | None = None

    @property
    def network(self) -> IPv4Net | None:
        return self.ip.network if self.ip else None


@dataclass
class Group:
    name: str
    subnet: IPv4Net
    gateway_device: str
    gateway_interface: str
    switch: str | None = None
    vlan: int = 1


@dataclass
class Host:
    name: str
    ip: ipaddress.IPv4Address
    group: str
    switch: str | None = None
    port: str | None = None


@dataclass
class Policies:
    default_acl_action: str = "permit"
    protected_subnets: list[IPv4Net] = field(default_factory=list)
    vlan_range: tuple[int, int] = (100, 999)
    reserved_vlans: set[int] = field(default_factory=set)
    p2p_convention: bool = False
    solution_weights: dict[str, int] = field(default_factory=dict)
    deployment: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policies":
        return cls(
            default_acl_action=d.get("default_acl_action", "permit"),
            protected_subnets=[IPv4Net(s) for s in d.get("protected_subnets", [])],
            vlan_range=tuple(d.get("vlan_range", [100, 999])),
            reserved_vlans=set(d.get("reserved_vlans", [])),
            p2p_convention=bool(d.get("p2p_convention", False)),
            solution_weights=d.get("solution_weights", {}),
            deployment=d.get("deployment", {}),
        )

    def probe_services(self) -> list[Service]:
        out = []
        for spec in self.deployment.get("probe_services", ["icmp"]):
            proto, _, port = str(spec).partition("/")
            out.append(Service(protocol=Protocol(proto), ports=[int(port)] if port else []))
        return out


def _ref(text: str) -> tuple[str, str]:
    dev, _, ifname = str(text).partition(":")
    if not ifname:
        raise KBError(f"expected DEVICE:INTERFACE, got {text!r}")
    return dev, ifname


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise KBError(f"missing knowledge-base file {path}")
    return yaml.safe_load(path.read_text()) or {}


class KnowledgeBase:
    def __init__(self, path: Path):
        self.path = Path(path)
        inv = _load_yaml(self.path / "inventory.yaml")
        topo = _load_yaml(self.path / "topology.yaml")
        self.policies = Policies.from_dict(_load_yaml(self.path / "policies.yaml"))

        defaults = inv.get("defaults", {})
        self.devices: dict[str, Device] = {}
        for name, spec in (inv.get("devices") or {}).items():
            spec = spec or {}
            mgmt = spec.get("mgmt") or {}
            self.devices[name] = Device(
                name=name,
                role=spec.get("role", "router"),
                vendor=spec.get("vendor", defaults.get("vendor", "cisco")),
                platform=spec.get("platform", defaults.get("platform", "cisco_ios")),
                os_version=str(spec.get("os_version", "")),
                capabilities=frozenset(spec.get("capabilities", [])),
                mgmt=Mgmt(host=str(mgmt.get("host", "")), port=int(mgmt.get("port", 22)),
                          transport=mgmt.get("transport", "ssh")),
                credentials={**defaults.get("credentials", {}), **spec.get("credentials", {})},
            )

        self.interfaces: dict[str, dict[str, Interface]] = {}
        for dev, spec in (topo.get("devices") or {}).items():
            if dev not in self.devices:
                raise KBError(f"topology device {dev} is missing from inventory.yaml")
            ifaces = {}
            for ifname, ispec in ((spec or {}).get("interfaces") or {}).items():
                ispec = ispec or {}
                ifaces[ifname] = Interface(
                    device=dev,
                    name=ifname,
                    ip=ipaddress.IPv4Interface(ispec["ip"]) if ispec.get("ip") else None,
                    description=ispec.get("description", ""),
                    mode=ispec.get("mode"),
                    vlan=ispec.get("vlan"),
                    tunnel=ispec.get("tunnel"),
                )
            self.interfaces[dev] = ifaces

        self.links = [(_ref(a), _ref(b)) for a, b in topo.get("links", [])]

        self.groups: dict[str, Group] = {}
        for name, g in (topo.get("groups") or {}).items():
            gdev, gif = _ref(g["gateway"])
            self.groups[name] = Group(name=name, subnet=IPv4Net(g["subnet"]), gateway_device=gdev,
                                      gateway_interface=gif, switch=g.get("switch"), vlan=int(g.get("vlan", 1)))

        self.hosts: dict[str, Host] = {}
        for name, h in (topo.get("hosts") or {}).items():
            sw, port = _ref(h["attach"]) if h.get("attach") else (None, None)
            self.hosts[name] = Host(name=name, ip=ipaddress.IPv4Address(h["ip"]), group=h["group"],
                                    switch=sw, port=port)

    # ---------------------------------------------------------------- lookups
    def interface(self, device: str, name: str) -> Interface | None:
        return self.interfaces.get(device, {}).get(name)

    def l3_interfaces(self, device: str) -> list[Interface]:
        return [i for i in self.interfaces.get(device, {}).values() if i.ip]

    def all_l3_interfaces(self) -> list[Interface]:
        return [i for dev in self.interfaces for i in self.l3_interfaces(dev)]

    def find_group(self, name: str) -> Group | None:
        return next((g for g in self.groups.values() if g.name.lower() == name.lower()), None)

    def find_host(self, name: str) -> Host | None:
        return next((h for h in self.hosts.values() if h.name.lower() == name.lower()), None)

    def group_at(self, device: str, interface: str) -> Group | None:
        return next((g for g in self.groups.values()
                     if g.gateway_device == device and g.gateway_interface == interface), None)

    def canonical(self, ep: Endpoint) -> Endpoint:
        """Return the endpoint with KB-canonical names; raise KBError if it does not exist."""
        if ep.group:
            g = self.find_group(ep.group)
            if not g:
                raise KBError(f"unknown group {ep.group!r} (known: {', '.join(self.groups)})")
            return Endpoint(group=g.name)
        if ep.host:
            h = self.find_host(ep.host)
            if not h:
                raise KBError(f"unknown host {ep.host!r} (known: {', '.join(self.hosts)})")
            return Endpoint(host=h.name)
        return ep

    def resolve(self, ep: Endpoint) -> IPv4Net:
        ep = self.canonical(ep)
        if ep.group:
            return self.groups[ep.group].subnet
        if ep.host:
            return IPv4Net(f"{self.hosts[ep.host].ip}/32")
        return IPv4Net(ep.subnet)

    def locate(self, net: IPv4Net) -> tuple[str, str] | None:
        """Router interface whose connected subnet contains `net` (longest match)."""
        best = None
        for itf in self.all_l3_interfaces():
            if itf.tunnel is None and net.subnet_of(itf.network):
                if best is None or itf.network.prefixlen > best.network.prefixlen:
                    best = itf
        return (best.device, best.name) if best else None

    def owner_of_ip(self, ip: str | ipaddress.IPv4Address) -> tuple[str, str, bool] | None:
        """(device, interface, is_local_address) of the router connected to `ip`."""
        addr = ipaddress.IPv4Address(ip)
        best = None
        for itf in self.all_l3_interfaces():
            if itf.ip.ip == addr:
                return itf.device, itf.name, True
            if addr in itf.network and (best is None or itf.network.prefixlen > best.network.prefixlen):
                best = itf
        return (best.device, best.name, False) if best else None

    def adjacency(self) -> dict[str, list[tuple[str, str, str]]]:
        """device -> [(neighbor, local_if, neighbor_if)] for routers sharing an L3 subnet."""
        adj: dict[str, list[tuple[str, str, str]]] = {d: [] for d in self.interfaces}
        ifaces = self.all_l3_interfaces()
        for a in ifaces:
            for b in ifaces:
                if a.device != b.device and a.network == b.network:
                    adj[a.device].append((b.device, a.name, b.name))
        for d in adj:
            adj[d].sort()
        return adj

    def host_by_ip(self, ip: str | ipaddress.IPv4Address) -> Host | None:
        addr = ipaddress.IPv4Address(ip)
        return next((h for h in self.hosts.values() if h.ip == addr), None)

    def representative_ip(self, net: IPv4Net) -> str:
        """A concrete address inside `net` used for simulation probes."""
        for h in self.hosts.values():
            if h.ip in net:
                return str(h.ip)
        if net.prefixlen >= 31:
            return str(net.network_address)
        return str(net.network_address + min(10, net.num_addresses - 2))

    def running_config(self, device: str) -> str | None:
        path = self.path / "configs" / f"{device}.cfg"
        return path.read_text() if path.is_file() else None

    def is_protected(self, ip: str) -> bool:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in n for n in self.policies.protected_subnets)

    # ---------------------------------------------------------------- LLM context
    def llm_context(self) -> str:
        lines = ["Groups (name: subnet, gateway):"]
        lines += [f"  - {g.name}: {g.subnet}, gateway {g.gateway_device} {g.gateway_interface}"
                  for g in self.groups.values()]
        lines.append("Hosts (name: ip, group):")
        lines += [f"  - {h.name}: {h.ip}, group {h.group}" for h in self.hosts.values()]
        lines.append("Devices:")
        for d in self.devices.values():
            ips = ", ".join(f"{i.name}={i.ip}" for i in self.l3_interfaces(d.name))
            lines.append(f"  - {d.name} ({d.role}, {d.platform}){': ' + ips if ips else ''}")
        lines.append("Infrastructure (protected) subnets: " + ", ".join(map(str, self.policies.protected_subnets)))
        return "\n".join(lines)

    # ---------------------------------------------------------------- consistency
    def check(self) -> list[Issue]:
        issues: list[Issue] = []
        issues += find_ip_conflicts(self.all_l3_interfaces())
        for (da, ia), (db, ib) in self.links:
            for d, i in ((da, ia), (db, ib)):
                if not self.interface(d, i):
                    issues.append(error(f"link references unknown interface {d}:{i}"))
        for g in self.groups.values():
            itf = self.interface(g.gateway_device, g.gateway_interface)
            if not itf or not itf.ip:
                issues.append(error(f"group {g.name}: gateway {g.gateway_device}:{g.gateway_interface} has no IP"))
            elif itf.ip.ip not in g.subnet:
                issues.append(error(f"group {g.name}: gateway {itf.ip} is outside {g.subnet}"))
            if g.switch and g.switch not in self.devices:
                issues.append(error(f"group {g.name}: unknown switch {g.switch}"))
        seen: dict[ipaddress.IPv4Address, str] = {}
        for h in self.hosts.values():
            g = self.groups.get(h.group)
            if not g:
                issues.append(error(f"host {h.name}: unknown group {h.group}"))
            elif h.ip not in g.subnet:
                issues.append(error(f"host {h.name}: {h.ip} is outside group subnet {g.subnet}"))
            if h.ip in seen:
                issues.append(error(f"host {h.name}: duplicate IP {h.ip} (also {seen[h.ip]})"))
            seen[h.ip] = h.name
            if h.switch and not self.interface(h.switch, h.port or ""):
                issues.append(error(f"host {h.name}: unknown switchport {h.switch}:{h.port}"))
        for dev in self.interfaces:
            for itf in self.interfaces[dev].values():
                if itf.vlan is not None and not 1 <= itf.vlan <= 4094:
                    issues.append(error(f"{dev} {itf.name}: invalid VLAN {itf.vlan}"))
        if self.policies.p2p_convention:
            issues += self._check_p2p_convention()
        return issues

    def _check_p2p_convention(self) -> list[Issue]:
        issues = []
        num = lambda d: int(m.group(1)) if (m := re.search(r"(\d+)$", d)) else None  # noqa: E731
        for a in self.all_l3_interfaces():
            peers = [b for b in self.all_l3_interfaces() if b.device != a.device and b.network == a.network]
            if not peers or a.network.prefixlen != 24:
                continue
            nums = sorted(n for n in (num(a.device), num(peers[0].device)) if n is not None)
            if len(nums) != 2:
                continue
            o = a.network.network_address.packed
            if (o[0], o[1], o[2]) != (10, nums[0], nums[1]):
                issues.append(warning(f"{a.device} {a.name} {a.network}: expected 10.{nums[0]}.{nums[1]}.0/24", a.device))
            if num(a.device) is not None and a.ip.ip.packed[3] != num(a.device):
                issues.append(warning(f"{a.device} {a.name} {a.ip}: expected host part .{num(a.device)}", a.device))
        return issues


def find_ip_conflicts(interfaces: list[Interface]) -> list[Issue]:
    """Duplicate addresses, and subnets that overlap without being the same link subnet."""
    issues = []
    for idx, a in enumerate(interfaces):
        for b in interfaces[idx + 1:]:
            if a.ip.ip == b.ip.ip:
                issues.append(error(f"duplicate IP {a.ip.ip} on {a.device} {a.name} and {b.device} {b.name}"))
            elif a.network != b.network and a.network.overlaps(b.network):
                issues.append(error(f"IP overlap: {a.device} {a.name} {a.network} vs {b.device} {b.name} {b.network}"))
            elif a.network == b.network and a.device == b.device:
                issues.append(error(f"{a.device}: {a.name} and {b.name} share subnet {a.network}"))
    return issues
