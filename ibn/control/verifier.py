"""Post-deployment reachability probes, chosen automatically with the simulator.

Routers can only originate pings, so we search router-sourced pings whose simulated result
*changes* because of this deployment (request or reply crosses the new policy) and add one
control probe that must keep working. Expected results come from the simulator, never guesses.
"""

from __future__ import annotations

from dataclasses import dataclass

from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.intent import Protocol
from ibn.models.netconfig import DeviceState
from ibn.validation.simulator import Flow, Simulator


@dataclass
class Probe:
    device: str
    source_interface: str
    source_ip: str
    target: str
    expected: bool
    purpose: str

    def __str__(self) -> str:
        return (f"{self.device}: ping {self.target} source {self.source_interface} "
                f"-> expect {'success' if self.expected else 'failure'} ({self.purpose})")


def _ping_ok(sim: Simulator, src: str, dst: str) -> bool:
    return sim.evaluate(Flow(src, dst, Protocol.ICMP)).allowed and sim.evaluate(Flow(dst, src, Protocol.ICMP)).allowed


def plan_probes(kb: KnowledgeBase, before: dict[str, DeviceState], after: dict[str, DeviceState],
                limit: int = 4) -> list[Probe]:
    sim_b, sim_a = Simulator(kb, before), Simulator(kb, after)
    targets = sorted({str(h.ip) for h in kb.hosts.values()} | {kb.representative_ip(g.subnet) for g in kb.groups.values()})
    observing, control = [], None
    for itf in kb.all_l3_interfaces():
        if itf.tunnel:
            continue
        src = str(itf.ip.ip)
        for dst in targets:
            if kb.owner_of_ip(dst)[:2] == (itf.device, itf.name):
                continue  # directly connected host: probe would not cross any router
            was, now = _ping_ok(sim_b, src, dst), _ping_ok(sim_a, src, dst)
            if was != now and len(observing) < limit:
                observing.append(Probe(itf.device, itf.name, src, dst, now, "observes the change"))
            elif was and now and control is None and kb.owner_of_ip(dst)[0] != itf.device:
                control = Probe(itf.device, itf.name, src, dst, True, "control: unaffected path still works")
    return observing + ([control] if control else [])
