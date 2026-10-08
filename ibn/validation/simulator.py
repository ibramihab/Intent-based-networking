"""Offline data-plane simulator over vendor-neutral DeviceModels parsed from device configs.

Models: L3 adjacency from configured interface addresses (shortest hop path, so HR<->Finance uses the
R1-R3 tunnel), shutdown interfaces, inbound/outbound ACLs (named, numbered, standard, extended),
zone-based firewall, null routes, and host isolation by access VLAN or shut switch ports.
Dynamic routing, NAT, PBR and QoS are not modelled: the validator reports them as limited verification.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass, field

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.dataplane import DeviceModel, Flow
from ibn.platforms import get_platform
from ibn.platforms.configtree import ConfigTree
from ibn.platforms.cisco_ios import APP_PORTS


@dataclass
class Verdict:
    allowed: bool
    trace: list[str] = field(default_factory=list)


def build_models(kb: KnowledgeBase, configs: dict[str, str | ConfigTree]) -> dict[str, DeviceModel]:
    models = {}
    for dev, cfg in configs.items():
        if dev not in kb.devices:
            continue
        platform = get_platform(kb.devices[dev].platform)
        tree = cfg if isinstance(cfg, ConfigTree) else platform.parse(cfg)
        model = platform.dataplane(tree, dev)
        if mgmt := kb.devices[dev].mgmt.interface:  # out-of-band management is not part of the data plane
            model.interfaces.pop(mgmt, None)
        models[dev] = model
    return models


class Simulator:
    def __init__(self, kb: KnowledgeBase, models: dict[str, DeviceModel]):
        self.kb = kb
        self.models = models
        self.adj = self._adjacency()

    # ---------------------------------------------------------------- topology
    def _adjacency(self) -> dict[str, list[tuple[str, str, str]]]:
        ifaces = [(d, i) for d, m in self.models.items() for i in m.l3_interfaces()]
        adj: dict[str, list[tuple[str, str, str]]] = {d: [] for d in self.models}
        for da, a in ifaces:
            for db, b in ifaces:
                if da != db and a.ip.network == b.ip.network:
                    adj[da].append((db, a.name, b.name))
        for d in adj:
            adj[d].sort()
        return adj

    def owner(self, ip: str) -> tuple[str, str, bool] | None:
        addr = ipaddress.IPv4Address(ip)
        best = None
        for dev, m in self.models.items():
            for itf in m.l3_interfaces():
                if itf.ip.ip == addr:
                    return dev, itf.name, True
                if addr in itf.ip.network and (best is None or itf.ip.network.prefixlen > best[2]):
                    best = (dev, itf.name, itf.ip.network.prefixlen)
        return (best[0], best[1], False) if best else None

    def _path(self, a: str, b: str) -> list[tuple[str, str, str]] | None:
        prev: dict[str, tuple[str, str, str] | None] = {a: None}
        queue = deque([a])
        while queue:
            cur = queue.popleft()
            if cur == b:
                break
            for nbr, local_if, nbr_if in self.adj.get(cur, []):
                if nbr not in prev:
                    prev[nbr] = (cur, local_if, nbr_if)
                    queue.append(nbr)
        if b not in prev:
            return None
        hops, node = [], b
        while prev[node]:
            hops.append(prev[node])
            node = prev[node][0]
        return list(reversed(hops))

    def _isolation(self, ip: str) -> str | None:
        host = self.kb.host_by_ip(ip)
        if not host or not host.switch or host.switch not in self.models:
            return None
        sw = self.models[host.switch]
        port = sw.interfaces.get(host.port or "")
        if port is None:
            return None
        if port.shutdown:
            return f"{host.name}: switch port {host.switch} {host.port} is shut down"
        group = self.kb.groups.get(host.group)
        uplink = None
        if group:
            for (da, ia), (db, ib) in self.kb.links:
                if (da, ia) == (group.gateway_device, group.gateway_interface) and db == host.switch:
                    uplink = sw.interfaces.get(ib)
                elif (db, ib) == (group.gateway_device, group.gateway_interface) and da == host.switch:
                    uplink = sw.interfaces.get(ia)
        if uplink and uplink.shutdown:
            return f"{host.name}: uplink {host.switch} {uplink.name} is shut down"
        if uplink and uplink.access_vlan != port.access_vlan:
            return f"{host.name} is in VLAN {port.access_vlan}, its gateway uplink in VLAN {uplink.access_vlan}"
        return None

    # ---------------------------------------------------------------- evaluation
    def evaluate(self, flow: Flow) -> Verdict:
        for ip in (flow.src, flow.dst):
            if why := self._isolation(ip):
                return Verdict(False, [why])
        src, dst = self.owner(flow.src), self.owner(flow.dst)
        if not src or not dst:
            return Verdict(False, ["no route: address not attached to any up router interface"])
        if src[:2] == dst[:2] and not src[2] and not dst[2]:
            return Verdict(True, [f"same L2 segment {src[0]} {src[1]}"])
        path = self._path(src[0], dst[0])
        if path is None:
            return Verdict(False, [f"no path {src[0]} -> {dst[0]}"])
        hops, in_if = [], None if src[2] else src[1]
        for dev, out_if, nxt_in in path:
            hops.append((dev, in_if, out_if))
            in_if = nxt_in
        hops.append((dst[0], in_if, None if dst[2] else dst[1]))

        trace = []
        for dev, i_in, i_out in hops:
            m = self.models[dev]
            trace.append(f"{dev} in={i_in or 'self'} out={i_out or 'self'}")
            if i_in and (acl := m.interfaces[i_in].acl_in):
                ok, why = self._acl(m, acl, flow)
                trace.append(f"  ACL in on {i_in}: {why}")
                if not ok:
                    return Verdict(False, trace)
            ok, why = self._zbf(m, i_in, i_out, flow)
            if why:
                trace.append(f"  ZBF: {why}")
            if not ok:
                return Verdict(False, trace)
            if i_out and (null := next((n for n in m.null_routes if ipaddress.IPv4Address(flow.dst) in n), None)):
                trace.append(f"  null route {null} drops the traffic")
                return Verdict(False, trace)
            if i_out and (acl := m.interfaces[i_out].acl_out):
                ok, why = self._acl(m, acl, flow)
                trace.append(f"  ACL out on {i_out}: {why}")
                if not ok:
                    return Verdict(False, trace)
        return Verdict(True, trace)

    @staticmethod
    def _acl(m: DeviceModel, name: str, flow: Flow) -> tuple[bool, str]:
        acl = m.acls.get(name)
        if acl is None:
            return True, f"{name} is not defined (an undefined ACL permits all)"
        return acl.evaluate(flow)

    def _zbf(self, m: DeviceModel, i_in: str | None, i_out: str | None, flow: Flow) -> tuple[bool, str]:
        if i_in is None or i_out is None:
            return True, ""  # traffic to/from the router itself (self zone)
        z_in, z_out = m.interfaces[i_in].zone, m.interfaces[i_out].zone
        if z_in is None and z_out is None:
            return True, ""
        if z_in is None or z_out is None:
            return False, f"{i_in}->{i_out}: traffic between a zoned and an unzoned interface is dropped"
        if z_in == z_out:
            return True, f"intra-zone {z_in}"
        pair = next((p for p in m.zone_pairs if p.src == z_in and p.dst == z_out), None)
        if pair is None:
            return False, f"no zone-pair {z_in}->{z_out}: dropped"
        policy = m.policies.get(pair.policy or "")
        if policy is None:
            return False, f"zone-pair {pair.name} has no inspect policy: dropped"
        for cls_name, action in policy.rules:
            cm = m.class_maps.get(cls_name)
            if cm and self._class_matches(m, cm, flow):
                return action != "drop", f"{pair.name} class {cls_name}: {action}"
        return policy.default_action != "drop", f"{pair.name} class-default: {policy.default_action}"

    def _class_matches(self, m: DeviceModel, cm, flow: Flow) -> bool:
        results = [self._acl(m, a, flow)[0] and a in m.acls for a in cm.acls]
        for proto in cm.protocols:
            if proto in ("tcp", "udp", "icmp"):
                results.append(flow.protocol == proto)
            elif proto in APP_PORTS:
                p, port = APP_PORTS[proto]
                results.append(flow.protocol == p and flow.port == port)
            else:
                results.append(False)
        if not results:
            return False
        return all(results) if cm.match_all else any(results)
