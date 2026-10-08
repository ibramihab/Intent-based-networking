"""Built-in offline data-plane simulator.

Models what IBN manages: L3 path (shortest hop over KB adjacencies, so HR<->Finance uses the
R1-R3 tunnel), IBN ACLs, zone-based firewall zone pairs and VLAN isolation of hosts.
Unmanaged config and dynamic routing are not modelled – use Batfish for full fidelity.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.intent import Action, Protocol
from ibn.models.netconfig import AccessList, DeviceState


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    protocol: Protocol
    port: int | None = None

    def __str__(self) -> str:
        svc = self.protocol.value + (f"/{self.port}" if self.port else "")
        return f"{self.src} -> {self.dst} {svc}"


@dataclass
class Verdict:
    allowed: bool
    trace: list[str] = field(default_factory=list)


class Simulator:
    def __init__(self, kb: KnowledgeBase, states: dict[str, DeviceState]):
        self.kb = kb
        self.states = states
        self.adj = kb.adjacency()

    def evaluate(self, flow: Flow) -> Verdict:
        trace: list[str] = []
        for ip in (flow.src, flow.dst):
            if (host := self.kb.host_by_ip(ip)) and (vlan := self._isolated_vlan(host)):
                return Verdict(False, [f"{host.name} is isolated in VLAN {vlan} on {host.switch}"])
        src, dst = self.kb.owner_of_ip(flow.src), self.kb.owner_of_ip(flow.dst)
        if not src or not dst:
            return Verdict(False, ["no route: address not attached to any router"])
        if src[:2] == dst[:2] and not src[2] and not dst[2]:
            return Verdict(True, [f"same L2 segment {src[0]} {src[1]}"])
        path = self._path(src[0], dst[0])
        if path is None:
            return Verdict(False, [f"no path {src[0]} -> {dst[0]}"])

        hops = []
        in_if = None if src[2] else src[1]
        for dev, out_if, nxt_in in path:
            hops.append((dev, in_if, out_if))
            in_if = nxt_in
        hops.append((dst[0], in_if, None if dst[2] else dst[1]))

        for dev, i_in, i_out in hops:
            trace.append(f"{dev} in={i_in or 'self'} out={i_out or 'self'}")
            state = self.states.get(dev)
            if not state:
                continue
            for iface, direction in ((i_in, "in"), (i_out, "out")):
                if iface and (b := state.binding(iface, direction)):
                    ok, why = self._acl(state.acl(b.acl), flow)
                    trace.append(f"  ACL {b.acl} {direction} on {iface}: {why}")
                    if not ok:
                        return Verdict(False, trace)
            if state.firewall:
                ok, why = self._zbf(state, i_in, i_out, flow)
                if why:
                    trace.append(f"  ZBF: {why}")
                if not ok:
                    return Verdict(False, trace)
        return Verdict(True, trace)

    def _isolated_vlan(self, host) -> int | None:
        state = self.states.get(host.switch or "")
        group = self.kb.groups.get(host.group)
        if not state or not group:
            return None
        port = next((p for p in state.access_ports if p.interface == host.port), None)
        return port.vlan if port and port.vlan != group.vlan else None

    def _path(self, a: str, b: str) -> list[tuple[str, str, str]] | None:
        """[(device, egress_if, next_device_ingress_if), ...] from a to b."""
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
            p_dev, p_if, n_if = prev[node]
            hops.append((p_dev, p_if, n_if))
            node = p_dev
        return list(reversed(hops))

    @staticmethod
    def _acl(acl: AccessList | None, flow: Flow) -> tuple[bool, str]:
        if acl is None:
            return True, "ACL not defined (IOS permits all)"
        for idx, rule in enumerate(acl.rules, 1):
            if rule.matches(flow.src, flow.dst, flow.protocol, flow.port):
                return rule.action == Action.PERMIT, f"rule {idx} {rule.action.value} ({rule.intent_id})"
        return acl.default_action == Action.PERMIT, f"default {acl.default_action.value}"

    @staticmethod
    def _zbf(state: DeviceState, i_in: str | None, i_out: str | None, flow: Flow) -> tuple[bool, str]:
        fw = state.firewall
        if i_in is None or i_out is None:
            return True, ""  # self zone: no self zone-pairs are configured by IBN
        z_in, z_out = fw.zones.get(i_in), fw.zones.get(i_out)
        if z_in is None and z_out is None:
            return True, ""
        if z_in is None or z_out is None:
            return False, f"{i_in}->{i_out}: traffic between zoned and unzoned interfaces is dropped"
        if z_in == z_out:
            return True, f"intra-zone {z_in}"
        pair = next((p for p in fw.zone_pairs if p.src_zone == z_in and p.dst_zone == z_out), None)
        if pair is None:
            return False, f"no zone-pair {z_in}->{z_out}"
        for idx, rule in enumerate(pair.rules, 1):
            if rule.matches(flow.src, flow.dst, flow.protocol, flow.port):
                verb = "inspect" if rule.action == Action.PERMIT else "drop"
                return rule.action == Action.PERMIT, f"{pair.name} class {idx} {verb} ({rule.intent_id})"
        return True, f"{pair.name} class-default pass"
