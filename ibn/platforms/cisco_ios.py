"""Cisco IOS / IOL platform: generic syntax checking, parsing into the data-plane model, references."""

from __future__ import annotations

import ipaddress
import re

from ibn.models.dataplane import Ace, Acl, ClassMap, DeviceModel, InspectPolicy, InterfaceState, PortMatch, ZonePair
from ibn.models.report import Issue, error, warning
from ibn.platforms.base import Platform, Ref
from ibn.platforms.configtree import ConfigTree

# ---------------------------------------------------------------------------- vocabulary
TOP_LEVEL = {
    "aaa", "access-list", "alias", "archive", "banner", "bridge", "call-home", "cdp", "class-map", "clock",
    "control-plane", "crypto", "default", "dial-peer", "dot1x", "errdisable", "ethernet", "event", "flow",
    "hostname", "interface", "ip", "ipv6", "key", "kron", "license", "line", "lldp", "logging", "mac",
    "mac-address-table", "monitor", "mpls", "multilink", "ntp", "object-group", "parameter-map", "policy-map",
    "port-channel", "privilege", "radius", "radius-server", "redundancy", "rmon", "route-map", "router",
    "scheduler", "service", "snmp-server", "spanning-tree", "tacacs", "tacacs-server", "template", "track",
    "udld", "username", "enable", "vlan", "vrf", "vtp", "zone", "zone-pair", "netconf", "restconf", "cts",
}
IP_TOP = {
    "access-list", "route", "nat", "domain", "domain-name", "domain-lookup", "name-server", "http", "ssh", "sla",
    "prefix-list", "dhcp", "routing", "cef", "multicast-routing", "vrf", "scp", "ftp", "tftp", "host",
    "default-gateway", "community-list", "as-path", "flow-export", "inspect", "forward-protocol", "local",
    "explicit-path", "source-route", "options", "icmp", "tcp", "arp", "finger", "bootp", "subnet-zero",
    "classless", "dns", "flow-cache", "ips", "admission", "wccp", "rcmd", "telnet", "pim", "msdp", "igmp",
    "audit", "port-map", "device", "radius", "tacacs", "ospf", "bgp-community", "extcommunity-list",
}
CHILD_VOCAB = {
    "interface": {"ip", "ipv6", "shutdown", "description", "switchport", "speed", "duplex", "mtu", "bandwidth",
                  "delay", "encapsulation", "tunnel", "zone-member", "service-policy", "channel-group",
                  "spanning-tree", "standby", "vrrp", "glbp", "cdp", "lldp", "keepalive", "load-interval",
                  "mac-address", "media-type", "negotiation", "storm-control", "power", "crypto", "vrf",
                  "logging", "carrier-delay", "dampening", "hold-queue", "arp", "ntp", "snmp", "traffic-shape",
                  "rate-limit", "mls", "udld", "authentication", "dot1x", "ppp", "clock", "fair-queue",
                  "random-detect", "priority-queue", "auto", "qos", "ospf", "pim", "flow", "nat", "default"},
    "acl": {"permit", "deny", "remark", "evaluate", "dynamic"},
    "class-map": {"match", "description"},
    "policy-map": {"class", "description", "parameter-map"},
    "policy-class": {"inspect", "pass", "drop", "police", "set", "bandwidth", "priority", "shape",
                     "service-policy", "queue-limit", "random-detect", "fair-queue", "log", "trust", "urlfpolicy"},
    "router": {"network", "neighbor", "redistribute", "passive-interface", "router-id", "area",
               "default-information", "distance", "maximum-paths", "auto-summary", "bgp", "address-family",
               "timers", "metric", "default-metric", "distribute-list", "eigrp", "log-adjacency-changes",
               "summary-address", "variance", "version", "offset-list", "synchronization", "aggregate-address",
               "exit-address-family", "ospf", "nsf", "bfd", "shutdown"},
    "line": {"login", "transport", "password", "exec-timeout", "access-class", "logging", "privilege", "history",
             "length", "width", "session-timeout", "stopbits", "speed", "exec", "autocommand", "authorization",
             "accounting", "ipv6"},
    "vlan": {"name", "state", "shutdown", "private-vlan", "remote-span", "mtu"},
    "zone": {"description"},
    "zone-pair": {"service-policy", "description"},
    "route-map": {"match", "set", "description", "continue"},
}
MODES = [  # (regex on a top-level line, mode name)
    (r"^interface ", "interface"), (r"^ip access-list extended ", "acl"),
    (r"^ip access-list standard ", "acl-std"), (r"^class-map\b", "class-map"),
    (r"^policy-map\b", "policy-map"), (r"^router ", "router"), (r"^line ", "line"), (r"^vlan \d", "vlan"),
    (r"^zone security ", "zone"), (r"^zone-pair security ", "zone-pair"), (r"^route-map ", "route-map"),
    (r"^(object-group|crypto|ip dhcp pool|key chain|control-plane|archive|parameter-map|ip sla|ip vrf|vrf "
     r"definition|ip access-list (role-based|resequence|logging)|ipv6 access-list|track|template|event|flow)",
     "other"),
]
IFACE_TYPES = {
    "ethernet": "Ethernet", "e": "Ethernet", "eth": "Ethernet", "et": "Ethernet",
    "fastethernet": "FastEthernet", "fa": "FastEthernet", "f": "FastEthernet",
    "gigabitethernet": "GigabitEthernet", "gi": "GigabitEthernet", "gig": "GigabitEthernet", "g": "GigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet", "te": "TenGigabitEthernet", "ten": "TenGigabitEthernet",
    "loopback": "Loopback", "lo": "Loopback", "tunnel": "Tunnel", "tu": "Tunnel", "tun": "Tunnel",
    "vlan": "Vlan", "vl": "Vlan", "port-channel": "Port-channel", "po": "Port-channel",
    "serial": "Serial", "se": "Serial", "null": "Null", "bdi": "BDI", "dialer": "Dialer",
    "virtual-template": "Virtual-Template", "nvi": "NVI",
}
LOGICAL = ("Loopback", "Tunnel", "Vlan", "Port-channel", "BDI", "Dialer", "Virtual-Template", "NVI", "Null")
PORT_NAMES = {
    "echo": 7, "discard": 9, "daytime": 13, "chargen": 19, "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23,
    "smtp": 25, "time": 37, "nameserver": 42, "whois": 43, "tacacs": 49, "domain": 53, "bootps": 67,
    "bootpc": 68, "tftp": 69, "gopher": 70, "finger": 79, "www": 80, "http": 80, "hostname": 101, "pop2": 109,
    "pop3": 110, "sunrpc": 111, "ident": 113, "nntp": 119, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138,
    "netbios-ss": 139, "snmp": 161, "snmptrap": 162, "xdmcp": 177, "bgp": 179, "irc": 194, "dnsix": 195,
    "https": 443, "isakmp": 500, "biff": 512, "exec": 512, "login": 513, "who": 513, "cmd": 514, "syslog": 514,
    "lpd": 515, "talk": 517, "rip": 520, "uucp": 540, "klogin": 543, "kshell": 544, "mobile-ip": 434,
    "pim-auto-rp": 496, "drip": 3949, "rdp": 3389,
}
APP_PORTS = {"http": ("tcp", 80), "https": ("tcp", 443), "ssh": ("tcp", 22), "telnet": ("tcp", 23),
             "ftp": ("tcp", 21), "smtp": ("tcp", 25), "dns": ("udp", 53), "domain": ("udp", 53),
             "ntp": ("udp", 123), "snmp": ("udp", 161), "tftp": ("udp", 69)}
PROTO_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp"}
IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"
ACE_FLAGS_WITH_ARG = {"dscp", "precedence", "tos", "time-range", "option", "ttl", "log-input", "reflect"}


class AceError(ValueError):
    pass


class Unmodeled(Exception):
    pass


def _address(tokens: list[str], i: int) -> tuple[ipaddress.IPv4Network, int]:
    if i >= len(tokens):
        raise AceError("missing address")
    tok = tokens[i]
    if tok == "any":
        return ipaddress.IPv4Network("0.0.0.0/0"), i + 1
    if tok == "host":
        if i + 1 >= len(tokens) or not re.fullmatch(IP_RE, tokens[i + 1]):
            raise AceError("'host' must be followed by an IP address")
        return ipaddress.IPv4Network(f"{_ip(tokens[i + 1])}/32"), i + 2
    if tok in ("object-group", "addrgroup"):
        raise Unmodeled("object-group addresses")
    if re.fullmatch(IP_RE, tok):
        addr = _ip(tok)
        if i + 1 < len(tokens) and re.fullmatch(IP_RE, tokens[i + 1]):
            wc = tokens[i + 1]
            try:
                net = ipaddress.IPv4Network(f"{addr}/{wc}")
            except ValueError:
                raise AceError(f"invalid or non-contiguous wildcard {addr} {wc}") from None
            return net, i + 2
        return ipaddress.IPv4Network(f"{addr}/32"), i + 1
    raise AceError(f"expected address, got {tok!r}")


def _ip(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise AceError(f"invalid IP address {text}") from None


def _port_value(tok: str) -> int | None:
    if tok.isdigit():
        port = int(tok)
        if not 0 <= port <= 65535:
            raise AceError(f"port {port} out of range")
        return port
    return PORT_NAMES.get(tok)


def _ports(tokens: list[str], i: int) -> tuple[PortMatch | None, int]:
    if i >= len(tokens) or tokens[i] not in ("eq", "neq", "gt", "lt", "range"):
        return None, i
    op, i = tokens[i], i + 1
    values = []
    want = 2 if op == "range" else (1 if op in ("gt", "lt") else 99)
    while i < len(tokens) and len(values) < want and (v := _port_value(tokens[i])) is not None:
        values.append(v)
        i += 1
    if not values or (op == "range" and len(values) != 2):
        raise AceError(f"'{op}' needs {'two ports' if op == 'range' else 'a port'}")
    return PortMatch(op, values), i


def parse_ace(text: str, standard: bool) -> Ace | None:
    """Parse one ACL entry (without the 'access-list N' prefix). None for remarks."""
    tokens = text.split()
    if tokens and tokens[0].isdigit():
        tokens = tokens[1:]
    if not tokens or tokens[0] in ("remark", "evaluate"):
        return None
    action = tokens[0]
    if action not in ("permit", "deny"):
        raise AceError(f"expected permit/deny, got {action!r}")
    if standard:
        src, i = _address(tokens, 1)
        return Ace(action, "ip", src, ipaddress.IPv4Network("0.0.0.0/0"), text=text)
    if len(tokens) < 4:
        raise AceError("extended entry needs protocol, source and destination")
    proto = PROTO_NUMBERS.get(tokens[1], tokens[1])
    if proto == "object-group":
        raise Unmodeled("object-group services")
    l4 = proto in ("tcp", "udp")
    src, i = _address(tokens, 2)
    sport, i = _ports(tokens, i) if l4 else (None, i)
    dst, i = _address(tokens, i)
    dport, i = _ports(tokens, i) if l4 else (None, i)
    rest = tokens[i:]
    if not l4 and any(t in ("eq", "neq", "gt", "lt", "range") for t in rest):
        raise AceError(f"port matching requires tcp/udp, not {proto}")
    return Ace(action, proto, src, dst, sport, dport, established="established" in rest, text=text)


def canonical_interface(name: str) -> str:
    m = re.match(r"^([A-Za-z-]+)\s*(\d.*)$", name.strip())
    if not m:
        return name.strip()
    kind = IFACE_TYPES.get(m.group(1).lower())
    return f"{kind}{m.group(2)}" if kind else name.strip()


class CiscoIOS(Platform):
    name = "cisco_ios"
    netmiko_device_type = "cisco_ios"
    error_patterns = ("% Invalid", "% Incomplete", "% Ambiguous", "% Unknown", "% Error", "% Cannot", "% Zone",
                      "% Bad", "% Access-list", "% Not allowed", "% Overlap", "% Duplicate")

    # ------------------------------------------------------------------ text helpers
    def normalize(self, commands: list[str]) -> list[str]:
        out = []
        for line in commands:
            m = re.match(r"^(\s*(?:no )?interface )(\S+(?:\s\d\S*)?)\s*$", line)
            out.append(m.group(1) + canonical_interface(m.group(2)) if m else line)
        return out

    def baseline_config(self, kb, device: str) -> str:
        lines = [f"hostname {device}"]
        for itf in kb.interfaces.get(device, {}).values():
            lines.append(f"interface {itf.name}")
            if itf.description:
                lines.append(f" description {itf.description}")
            if itf.ip:
                lines.append(f" ip address {itf.ip.ip} {itf.ip.netmask}")
            if itf.tunnel:
                lines.append(f" tunnel source {itf.tunnel.get('source')}")
                lines.append(f" tunnel destination {itf.tunnel.get('destination')}")
            if itf.mode == "access":
                lines.append(" switchport mode access")
                if itf.vlan and itf.vlan != 1:
                    lines.append(f" switchport access vlan {itf.vlan}")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------ syntax
    def syntax_check(self, commands: list[str]) -> list[Issue]:
        issues: list[Issue] = []
        stack: list[tuple[int, str]] = []
        for n, raw in enumerate(commands, 1):
            line = raw.rstrip()
            s = line.strip()
            if not s or s.startswith("!"):
                continue
            where = f"line {n} '{s}'"
            if s in ("end", "exit"):
                if stack:
                    stack.pop()
                continue
            if "\t" in line:
                issues.append(error(f"{where}: use spaces, not tabs"))
            indent = len(line) - len(line.lstrip(" "))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            mode = stack[-1][1] if stack else None
            negated = s.startswith("no ")
            body = s[3:] if negated else s
            toks = body.split()
            if indent > 0 and mode is None:
                issues.append(error(f"{where}: indented, but the previous line does not enter a sub-mode"))
                continue
            try:
                if mode is None:
                    issues += self._check_top(where, body, toks)
                else:
                    issues += self._check_child(where, mode, body, toks, negated)
            except AceError as exc:
                issues.append(error(f"{where}: {exc}"))
            except Unmodeled:
                pass
            new_mode = self._mode_of(body, mode)
            if new_mode and not negated:
                stack.append((indent, new_mode))
        return issues

    @staticmethod
    def _mode_of(body: str, parent: str | None) -> str | None:
        if parent is None:
            return next((m for rx, m in MODES if re.match(rx, body)), None)
        if parent == "policy-map" and body.startswith("class "):
            return "policy-class"
        if parent in ("router", "other", "policy-class") and body.startswith(("address-family", "class ")):
            return "other"
        return None

    def _check_top(self, where: str, body: str, toks: list[str]) -> list[Issue]:
        if toks[0] not in TOP_LEVEL:
            return [error(f"{where}: unknown global command '{toks[0]}' (exec commands such as show/write/copy "
                          "are not allowed; sub-mode commands must be indented)")]
        if toks[0] == "ip" and (len(toks) < 2 or toks[1] not in IP_TOP):
            return [error(f"{where}: 'ip {toks[1] if len(toks) > 1 else ''}' is not a global command "
                          "(indent it under its interface or mode)")]
        if toks[0] == "interface":
            name = " ".join(toks[1:])
            canon = canonical_interface(name)
            if not re.fullmatch(r"[A-Za-z-]+\d+(/\d+)*(\.\d+)?", canon):
                return [error(f"{where}: invalid interface name '{name}'")]
            if canon != name:
                return [warning(f"{where}: abbreviated interface name, prefer '{canon}'")]
        if toks[0] == "access-list" and len(toks) > 2:
            num = toks[1]
            if not num.isdigit():
                return [error(f"{where}: numbered ACL expected")]
            standard = 1 <= int(num) <= 99 or 1300 <= int(num) <= 1999
            parse_ace(" ".join(toks[2:]), standard)
        if body.startswith("ip route "):
            return self._check_route(where, toks)
        if toks[0] == "vlan" and len(toks) > 1:
            return self._check_vlan_list(where, toks[1])
        if body.startswith("ip access-list ") and (len(toks) < 4 or toks[2] not in
                                                   ("extended", "standard", "role-based", "logging", "resequence")):
            return [error(f"{where}: expected 'ip access-list extended|standard NAME'")]
        return []

    def _check_child(self, where: str, mode: str, body: str, toks: list[str], negated: bool) -> list[Issue]:
        vocab = CHILD_VOCAB.get("acl" if mode == "acl-std" else mode)
        if mode in ("acl", "acl-std"):
            if toks[0].isdigit() and (negated or len(toks) == 1):
                return []
            if not (toks[0].isdigit() or toks[0] in vocab):
                return [error(f"{where}: not a valid ACL entry")]
            parse_ace(body, standard=mode == "acl-std")
            return []
        if vocab is not None and toks[0] not in vocab:
            return [error(f"{where}: '{toks[0]}' is not valid in {mode} mode")]
        if mode == "interface" and body.startswith("ip address ") and len(toks) >= 4:
            return self._check_address(where, toks[2], toks[3])
        if mode == "interface" and body.startswith("switchport access vlan"):
            return self._check_vlan_list(where, toks[-1])
        return []

    @staticmethod
    def _check_address(where: str, addr: str, mask: str) -> list[Issue]:
        try:
            itf = ipaddress.IPv4Interface(f"{addr}/{mask}")
        except ValueError:
            return [error(f"{where}: invalid address/mask {addr} {mask}")]
        net = itf.network
        if net.prefixlen < 31 and itf.ip in (net.network_address, net.broadcast_address):
            return [error(f"{where}: {addr} is the network or broadcast address of {net}")]
        return []

    @staticmethod
    def _check_route(where: str, toks: list[str]) -> list[Issue]:
        if len(toks) < 5:
            return [error(f"{where}: expected 'ip route PREFIX MASK NEXT-HOP|INTERFACE'")]
        try:
            ipaddress.IPv4Network(f"{toks[2]}/{toks[3]}")
        except ValueError:
            return [error(f"{where}: invalid prefix/mask {toks[2]} {toks[3]} (host bits set?)")]
        return []

    @staticmethod
    def _check_vlan_list(where: str, spec: str) -> list[Issue]:
        for part in re.split(r"[,-]", spec):
            if not part.isdigit() or not 1 <= int(part) <= 4094:
                return [error(f"{where}: invalid VLAN id {part!r}")]
        return []

    # ------------------------------------------------------------------ data plane
    def dataplane(self, tree: ConfigTree, device: str) -> DeviceModel:
        m = DeviceModel(name=device)
        for node in tree.top("interface"):
            itf = InterfaceState(name=canonical_interface(node.text[len("interface "):]))
            for c in node.children:
                t = c.text.split()
                if c.text.startswith("ip address ") and len(t) >= 4 and "secondary" not in t:
                    try:
                        itf.ip = ipaddress.IPv4Interface(f"{t[2]}/{t[3]}")
                    except ValueError:
                        m.notes.append(f"{itf.name}: unparsable address")
                elif c.text == "shutdown":
                    itf.shutdown = True
                elif c.text.startswith("ip access-group ") and len(t) == 4:
                    setattr(itf, "acl_in" if t[3] == "in" else "acl_out", t[2])
                elif c.text.startswith("zone-member security "):
                    itf.zone = t[2]
                elif c.text.startswith("switchport access vlan ") and t[-1].isdigit():
                    itf.access_vlan = int(t[-1])
            m.interfaces[itf.name] = itf

        for node in tree.top("ip access-list"):
            t = node.text.split()
            if len(t) < 4 or t[2] not in ("extended", "standard"):
                continue
            acl = m.acls.setdefault(t[3], Acl(t[3]))
            seq, ordered = 0, []
            for c in node.children:  # IOS evaluates by sequence number; unnumbered entries get last + 10
                first = c.text.split()[0]
                seq = int(first) if first.isdigit() else seq + 10
                ordered.append((seq, c.text))
            for _, text in sorted(ordered, key=lambda x: x[0]):
                self._add_ace(m, acl, text, t[2] == "standard")
        for node in tree.top("access-list"):
            t = node.text.split()
            if len(t) > 2 and t[1].isdigit():
                n = int(t[1])
                acl = m.acls.setdefault(t[1], Acl(t[1]))
                self._add_ace(m, acl, " ".join(t[2:]), 1 <= n <= 99 or 1300 <= n <= 1999)

        for node in tree.top("class-map"):
            t = node.text.split()
            if "inspect" not in t:
                m.notes.append(f"class-map {t[-1]} (non-inspect class-maps are not simulated)")
                continue
            cm = ClassMap(name=t[-1], match_all="match-any" not in t)
            for c in node.children:
                ct = c.text.split()
                if c.text.startswith("match access-group name "):
                    cm.acls.append(ct[3])
                elif c.text.startswith("match access-group ") and ct[-1].isdigit():
                    cm.acls.append(ct[-1])
                elif c.text.startswith("match protocol "):
                    cm.protocols.append(ct[2])
            m.class_maps[cm.name] = cm

        for node in tree.top("policy-map"):
            t = node.text.split()
            if "inspect" not in t:
                m.notes.append(f"policy-map {t[-1]} (QoS policies are not simulated)")
                continue
            pol = InspectPolicy(name=t[-1])
            for c in node.children:
                ct = c.text.split()
                action = next((g.text.split()[0] for g in c.children
                               if g.text.split()[0] in ("inspect", "pass", "drop")), "drop")
                if c.text == "class class-default":
                    pol.default_action = action
                elif c.text.startswith("class "):
                    pol.rules.append((ct[-1], action))
            m.policies[pol.name] = pol

        for node in tree.top("zone-pair security"):
            t = node.text.split()
            if len(t) >= 7:
                policy = next((c.text.split()[-1] for c in node.children
                               if c.text.startswith("service-policy type inspect")), None)
                m.zone_pairs.append(ZonePair(t[2], t[4], t[6], policy))

        for node in tree.top("ip route"):
            t = node.text.split()
            if len(t) >= 5 and t[4].lower().startswith("null"):
                try:
                    m.null_routes.append(ipaddress.IPv4Network(f"{t[2]}/{t[3]}"))
                except ValueError:
                    pass
        for node in tree.top("vlan"):
            spec = node.text.split()[1] if len(node.text.split()) > 1 else ""
            for part in spec.split(","):
                if part.isdigit():
                    m.vlans.add(int(part))
        return m

    @staticmethod
    def _add_ace(m: DeviceModel, acl: Acl, text: str, standard: bool) -> None:
        try:
            ace = parse_ace(text, standard)
        except Unmodeled as exc:
            m.notes.append(f"ACL {acl.name} uses {exc}; entry ignored by the simulator")
            return
        except AceError:
            m.notes.append(f"ACL {acl.name}: unparsable entry '{text}'")
            return
        if ace:
            acl.entries.append(ace)

    # ------------------------------------------------------------------ references
    def references(self, tree: ConfigTree) -> tuple[set[tuple[str, str]], list[Ref]]:
        defined: set[tuple[str, str]] = {("zone", "self"), ("class-map", "class-default")}
        refs: list[Ref] = []
        for node in tree.root.children:
            t = node.text.split()
            if node.text.startswith("ip access-list ") and len(t) >= 4:
                defined.add(("acl", t[3]))
            elif t[0] == "access-list" and len(t) > 1:
                defined.add(("acl", t[1]))
            elif t[0] in ("class-map", "policy-map") and len(t) > 1:
                defined.add((t[0], t[-1]))
            elif node.text.startswith("zone security ") and len(t) > 2:
                defined.add(("zone", t[2]))
            elif t[0] == "route-map" and len(t) > 1:
                defined.add(("route-map", t[1]))
            elif node.text.startswith("ip prefix-list ") and len(t) > 2:
                defined.add(("prefix-list", t[2]))
            elif t[0] == "object-group" and len(t) > 2:
                defined.add(("object-group", t[2]))
            elif t[0] == "interface" and len(t) > 1:
                defined.add(("interface", canonical_interface(" ".join(t[1:]))))
            elif node.text.startswith("zone-pair security ") and len(t) >= 7:
                refs += [Ref("zone", t[4], node.text), Ref("zone", t[6], node.text)]
            elif node.text.startswith("ip nat ") and " list " in node.text:
                refs.append(Ref("acl", t[t.index("list") + 1], node.text))
            for _, c in node.walk():
                refs += self._child_refs(node.text, c.text)
        return defined, refs

    @staticmethod
    def _child_refs(parent: str, text: str) -> list[Ref]:
        t = text.split()
        where = f"{parent} > {text}"
        if text.startswith("ip access-group ") and len(t) >= 3:
            return [Ref("acl", t[2], where)]
        if text.startswith("access-class ") and len(t) >= 2:
            return [Ref("acl", t[1], where)]
        if text.startswith("match access-group name ") and len(t) >= 4:
            return [Ref("acl", t[3], where)]
        if text.startswith("match access-group ") and len(t) >= 3:
            return [Ref("acl", t[2], where)]
        if text.startswith("match ip address prefix-list ") and len(t) >= 5:
            return [Ref("prefix-list", n, where) for n in t[4:]]
        if text.startswith("match ip address ") and len(t) >= 4:
            return [Ref("acl", n, where) for n in t[3:]]
        if text.startswith("class ") and parent.startswith("policy-map") and t[-1] != "class-default":
            return [Ref("class-map", t[-1], where)]
        if text.startswith("service-policy ") and len(t) >= 2:
            return [Ref("policy-map", t[-1], where)]
        if text.startswith("zone-member security ") and len(t) >= 3:
            return [Ref("zone", t[2], where)]
        if text.startswith("ip policy route-map ") or (" route-map " in f" {text} " and t[0] in
                                                        ("neighbor", "redistribute", "default-information")):
            return [Ref("route-map", t[t.index("route-map") + 1], where)] if t.index("route-map") + 1 < len(t) else []
        if text.startswith("tunnel source ") and len(t) == 3 and not re.fullmatch(IP_RE, t[2]):
            return [Ref("interface", canonical_interface(t[2]), where)]
        if "object-group" in t and t.index("object-group") + 1 < len(t):
            return [Ref("object-group", t[t.index("object-group") + 1], where)]
        return []

    def interface_commands(self, tree: ConfigTree) -> dict[str, list[str]]:
        return {canonical_interface(n.text[len("interface "):]): [c.text for c in n.children]
                for n in tree.top("interface")}

    # ------------------------------------------------------------------ simulation coverage
    def unmodeled(self, commands: list[str]) -> list[str]:
        notes: list[str] = []

        def note(text: str) -> None:
            if text not in notes:
                notes.append(text)

        harmless_top = ("hostname", "banner", "logging", "snmp-server", "ntp", "service", "clock", "alias",
                        "archive", "cdp", "lldp", "ip domain", "ip name-server", "ip ssh", "ip http", "username",
                        "enable", "line", "aaa", "key", "privilege")
        modeled_iface = ("ip address", "shutdown", "ip access-group", "zone-member security", "switchport access vlan",
                         "switchport mode access", "description")
        parent = None
        for raw in commands:
            if not raw.strip() or raw.strip() in ("exit", "end"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            s = raw.strip()
            body = s[3:] if s.startswith("no ") else s
            if indent == 0:
                parent = body
                if body.startswith(("ip access-list extended", "ip access-list standard", "interface",
                                    "zone security", "zone-pair security", "class-map type inspect",
                                    "policy-map type inspect", "vlan")) or body.startswith(harmless_top):
                    continue
                if body.startswith("access-list "):
                    if "object-group" in body:
                        note("object-group in ACL entries")
                    continue
                if body.startswith("ip route "):
                    if not re.search(r"\bnull\s*0\b", body, re.I):
                        note("static route (path changes are not simulated)")
                    continue
                if body.startswith("router "):
                    note(f"routing protocol ({' '.join(body.split()[:2])})")
                elif body.startswith("ip nat"):
                    note("NAT")
                elif body.startswith("route-map"):
                    note("route-map / policy-based routing")
                elif body.startswith(("class-map", "policy-map")):
                    note("QoS class-map/policy-map")
                elif body.startswith("object-group"):
                    note("object-group")
                else:
                    note(f"'{' '.join(body.split()[:2])}'")
            elif parent and parent.startswith("interface"):
                if not body.startswith(modeled_iface):
                    note(f"interface setting '{' '.join(body.split()[:3])}'")
            elif parent and parent.startswith(("ip access-list", "class-map", "policy-map")) and "object-group" in body:
                note("object-group in ACL entries")
            elif parent and parent.startswith("class-map type inspect") and body.startswith("match protocol ") \
                    and body.split()[-1] not in APP_PORTS and body.split()[-1] not in ("tcp", "udp", "icmp"):
                note(f"inspect protocol '{body.split()[-1]}'")
        return notes

    # ------------------------------------------------------------------ control
    def ping_command(self, target: str, source_interface: str | None) -> str:
        src = f" source {source_interface}" if source_interface else ""
        return f"ping {target}{src} repeat 3 timeout 1"

    def ping_succeeded(self, output: str) -> bool:
        m = re.search(r"Success rate is (\d+) percent", output)
        return bool(m and int(m.group(1)) > 0)
