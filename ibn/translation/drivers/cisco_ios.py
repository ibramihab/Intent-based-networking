"""Cisco IOS / IOL driver: Jinja2 templates for rendering, regex grammar for offline syntax checks."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from ibn.models.intent import Action
from ibn.models.netconfig import DeviceState, FirewallConfig, PolicyRule
from ibn.models.report import Issue, error, warning
from ibn.translation.drivers.base import Check, VendorDriver

_ENV = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates" / "cisco_ios"),
                   trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined, keep_trailing_newline=False)

NAME = r"[A-Za-z][\w-]{0,63}"
IFACE = r"(?:Ethernet|GigabitEthernet|FastEthernet|TenGigabitEthernet|Tunnel|Vlan|Loopback|Port-channel)\d+(?:/\d+)*(?:\.\d+)?"
IP = r"\d{1,3}(?:\.\d{1,3}){3}"
ADDR = rf"(?:any|host {IP}|{IP} {IP})"

GRAMMAR = [re.compile(p) for p in (
    rf"^(no )?ip access-list extended {NAME}$",
    r"^ remark .{1,100}$",
    rf"^ \d+ (permit|deny) (ip|icmp|tcp|udp) {ADDR} {ADDR}( eq \d{{1,5}})?$",
    rf"^interface {IFACE}$",
    rf"^ (no )?ip access-group {NAME} (in|out)$",
    rf"^(no )?zone security {NAME}$",
    rf"^ (no )?zone-member security {NAME}$",
    rf"^(no )?class-map type inspect match-any {NAME}$",
    rf"^ match access-group name {NAME}$",
    rf"^(no )?policy-map type inspect {NAME}$",
    rf"^ class (type inspect {NAME}|class-default)$",
    r"^  (inspect|drop log|drop|pass)$",
    rf"^zone-pair security {NAME} source {NAME} destination {NAME}$",
    rf"^no zone-pair security {NAME}$",
    rf"^ (no )?service-policy type inspect {NAME}$",
    r"^(no )?vlan \d{1,4}$",
    r"^ name [\w-]{1,32}$",
    r"^ switchport mode access$",
    r"^ switchport access vlan \d{1,4}$",
)]


def _addr(cidr: str) -> str:
    net = ipaddress.IPv4Network(cidr)
    if net.prefixlen == 0:
        return "any"
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


def _aces(rules: list[PolicyRule], default: Action | None, force_permit: bool = False) -> list[str]:
    lines, seq, last_intent = [], 10, None
    for rule in rules:
        if rule.intent_id and rule.intent_id != last_intent:
            lines.append(f"remark IBN intent {rule.intent_id}")
            last_intent = rule.intent_id
        action = "permit" if force_permit else rule.action.value
        for port in rule.ports or [None]:
            eq = f" eq {port}" if port else ""
            lines.append(f"{seq} {action} {rule.protocol.value} {_addr(rule.src)} {_addr(rule.dst)}{eq}")
            seq += 10
    if default is not None:
        lines.append(f"{seq} {default.value} ip any any")
    return lines


def _fw(state: DeviceState) -> FirewallConfig:
    return state.firewall or FirewallConfig()


class CiscoIOSDriver(VendorDriver):
    platform = "cisco_ios"
    netmiko_device_type = "cisco_ios"
    error_patterns = ("% Invalid", "% Incomplete", "% Ambiguous", "% Unknown", "% Error", "% Cannot", "% Zone")

    # ------------------------------------------------------------------ rendering
    def render_transition(self, before: DeviceState, after: DeviceState) -> list[str]:
        text = "\n".join(self._vlans(before, after) + self._acls(before, after) + self._firewall(before, after))
        return [ln.rstrip() for ln in text.splitlines() if ln.strip()]

    def _vlans(self, before: DeviceState, after: DeviceState) -> list[str]:
        out = []
        old_ids = {v.id for v in before.vlans}
        new_ids = {v.id for v in after.vlans}
        out += [_ENV.get_template("vlan.j2").render(vlan=v) for v in after.vlans if v.id not in old_ids]
        old_ports = {p.interface: p.vlan for p in before.access_ports}
        out += [_ENV.get_template("access_port.j2").render(port=p)
                for p in after.access_ports if old_ports.get(p.interface) != p.vlan]
        out += [f"no vlan {v.id}" for v in before.vlans if v.id not in new_ids]
        return out

    def _acls(self, before: DeviceState, after: DeviceState) -> list[str]:
        out = []
        old_names = {a.name for a in before.acls}
        new_names = {a.name for a in after.acls}
        for acl in after.acls:
            if acl.name not in old_names:
                out.append(_ENV.get_template("acl.j2").render(name=acl.name, aces=_aces(acl.rules, acl.default_action)))
        for b in after.bindings:
            old = before.binding(b.interface, b.direction)
            if not old or old.acl != b.acl:
                out.append(f"interface {b.interface}\n ip access-group {b.acl} {b.direction}")
        for b in before.bindings:
            if not after.binding(b.interface, b.direction):
                out.append(f"interface {b.interface}\n no ip access-group {b.acl} {b.direction}")
        out += [f"no ip access-list extended {a.name}" for a in before.acls if a.name not in new_names]
        return out

    def _firewall(self, before: DeviceState, after: DeviceState) -> list[str]:
        fb, fa = _fw(before), _fw(after)
        out = []
        old_zones, new_zones = set(fb.zones.values()), set(fa.zones.values())
        old_pols = {p.policy: p for p in fb.zone_pairs}
        new_pols = {p.policy: p for p in fa.zone_pairs}
        old_pairs = {p.name: p for p in fb.zone_pairs}
        new_pairs = {p.name: p for p in fa.zone_pairs}

        out += [f"zone security {z}" for z in sorted(new_zones - old_zones)]
        for pol, pair in new_pols.items():
            if pol not in old_pols:
                classes = [{"name": f"{pol}_C{i}", "acl": f"{pol}_A{i}", "aces": _aces([r], None, force_permit=True),
                            "action": "drop log" if r.action == Action.DENY else "inspect"}
                           for i, r in enumerate(pair.rules, 1)]
                out.append(_ENV.get_template("zbf_policy.j2").render(policy=pol, classes=classes))
        for name, pair in new_pairs.items():
            old = old_pairs.get(name)
            if not old or old.policy != pair.policy:
                out.append(_ENV.get_template("zone_pair.j2").render(pair=pair, old_policy=old.policy if old else None))
        # zone membership last, so traffic always has a zone-pair policy to hit
        for iface, zone in sorted(fa.zones.items()):
            old = fb.zones.get(iface)
            if old != zone:
                out.append(f"interface {iface}" + (f"\n no zone-member security {old}" if old else "")
                           + f"\n zone-member security {zone}")
        # removals in reverse dependency order
        for iface, zone in sorted(fb.zones.items()):
            if iface not in fa.zones:
                out.append(f"interface {iface}\n no zone-member security {zone}")
        out += [f"no zone-pair security {n}" for n in old_pairs if n not in new_pairs]
        for pol, pair in old_pols.items():
            if pol not in new_pols:
                out.append(f"no policy-map type inspect {pol}")
                for i in range(1, len(pair.rules) + 1):
                    out += [f"no class-map type inspect match-any {pol}_C{i}", f"no ip access-list extended {pol}_A{i}"]
        out += [f"no zone security {z}" for z in sorted(old_zones - new_zones)]
        return out

    # ------------------------------------------------------------------ validation
    def validate_syntax(self, commands: list[str]) -> list[Issue]:
        issues = []
        for n, line in enumerate(commands, 1):
            if not any(g.match(line) for g in GRAMMAR):
                issues.append(error(f"line {n}: unrecognised IOS syntax: {line!r}"))
                continue
            for ip in re.findall(IP, line):
                try:
                    ipaddress.IPv4Address(ip)
                except ValueError:
                    issues.append(error(f"line {n}: invalid address {ip}"))
            if " permit " in line or " deny " in line:
                tokens, i = line.split(), 0
                while i < len(tokens) - 1:
                    if tokens[i] == "host":
                        i += 2
                    elif re.fullmatch(IP, tokens[i]) and re.fullmatch(IP, tokens[i + 1]):
                        issues += self._check_wildcard(n, tokens[i], tokens[i + 1])
                        i += 2
                    else:
                        i += 1
            if m := re.search(r" eq (\d+)$", line):
                if not 1 <= int(m.group(1)) <= 65535:
                    issues.append(error(f"line {n}: port {m.group(1)} out of range"))
                if not re.search(r" (tcp|udp) ", line):
                    issues.append(error(f"line {n}: port match requires tcp/udp"))
            if m := re.search(r"vlan (\d+)$", line):
                if not 1 <= int(m.group(1)) <= 4094:
                    issues.append(error(f"line {n}: VLAN {m.group(1)} out of range"))
        return issues

    @staticmethod
    def _check_wildcard(n: int, ip: str, wc: str) -> list[Issue]:
        try:
            net = ipaddress.IPv4Network(f"{ip}/{wc}")  # accepts hostmask form when contiguous
        except ValueError:
            return [error(f"line {n}: non-contiguous or invalid wildcard {wc}")]
        if str(net.network_address) != ip:
            return [warning(f"line {n}: {ip} has host bits set for wildcard {wc}")]
        return []

    def verification_checks(self, before: DeviceState, after: DeviceState) -> list[Check]:
        checks = []
        for b in after.bindings:
            checks.append(Check(f"show running-config interface {b.interface}", [f"ip access-group {b.acl} {b.direction}"]))
        for b in before.bindings:
            if not after.binding(b.interface, b.direction):
                checks.append(Check(f"show running-config interface {b.interface}", [],
                                    [f"ip access-group {b.acl} {b.direction}"]))
        new_names = {a.name for a in after.acls}
        checks += [Check(f"show ip access-lists {a.name}", [f"Extended IP access list {a.name}"]) for a in after.acls]
        checks += [Check(f"show ip access-lists {a.name}", [], [f"Extended IP access list {a.name}"])
                   for a in before.acls if a.name not in new_names]
        fa, fb = _fw(after), _fw(before)
        for pair in fa.zone_pairs:
            checks.append(Check(f"show running-config | section zone-pair security {pair.name}",
                                [f"service-policy type inspect {pair.policy}"]))
        for iface, zone in fa.zones.items():
            checks.append(Check(f"show running-config interface {iface}", [f"zone-member security {zone}"]))
        for iface, zone in fb.zones.items():
            if iface not in fa.zones:
                checks.append(Check(f"show running-config interface {iface}", [], [f"zone-member security {zone}"]))
        for p in after.access_ports:
            cmd = f"show running-config interface {p.interface}"
            checks.append(Check(cmd, [], ["switchport access vlan"]) if p.vlan == 1
                          else Check(cmd, [f"switchport access vlan {p.vlan}"]))
        if after.vlans:
            checks.append(Check("show vlan brief", [str(v.id) for v in after.vlans]))
        return checks

    def ping_command(self, target: str, source_interface: str | None) -> str:
        src = f" source {source_interface}" if source_interface else ""
        return f"ping {target}{src} repeat 3 timeout 1"

    def ping_succeeded(self, output: str) -> bool:
        m = re.search(r"Success rate is (\d+) percent", output)
        return bool(m and int(m.group(1)) > 0)
