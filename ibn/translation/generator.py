"""Config Generator.

Step 1 – vendor-neutral: compute the desired *managed* state of every device from ALL active
intents (plus the new ones). One ACL per interface/direction, one policy per zone pair, so
intents compose instead of fighting over the same interface.
Step 2 – device-specific: hand before/after to the platform driver, which renders the commands
and (by rendering after -> before) the exact rollback.

Changed objects get a new revision suffix (…_R<n>) so ACL/policy swaps are hitless:
define new -> rebind -> delete old.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from ibn.intent.space import TrafficSpace, specificity
from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.intent import Action, Intent, SolutionKind
from ibn.models.netconfig import (AccessList, AccessPort, AclBinding, CandidateConfig, DeviceChange, DeviceState,
                                  FirewallConfig, PolicyRule, Vlan, ZonePair)
from ibn.translation.drivers import get_driver
from ibn.translation.placement import acl_placement, device_zones, directional_rules, firewall_placement


class GenerationError(Exception):
    pass


def short_if(name: str) -> str:
    """Ethernet0/2 -> E0_2, Tunnel0 -> T0 (for object names)."""
    head = name.rstrip("0123456789/.:")
    return (head[:1] + name[len(head):]).replace("/", "_").replace(".", "_").replace(":", "_").upper()


def _rule_key(intent: Intent, rule: PolicyRule):
    space = TrafficSpace(ipaddress.IPv4Network(rule.src), ipaddress.IPv4Network(rule.dst),
                         rule.protocol, frozenset(rule.ports))
    spec = specificity(space)
    return (-intent.priority, tuple(-x for x in spec), intent.created_at, intent.id)


def desired_states(kb: KnowledgeBase, records: list[tuple[Intent, SolutionKind]],
                   current: dict[str, DeviceState]) -> dict[str, DeviceState]:
    acl_rules: dict[tuple[str, str, str], list] = defaultdict(list)
    fw_rules: dict[tuple[str, str, str], list] = defaultdict(list)
    isolate: dict[tuple[str, str], str] = {}  # (switch, port) -> host

    for intent, kind in records:
        if kind == SolutionKind.VLAN:
            host = kb.hosts[intent.source.host]
            isolate[(host.switch, host.port)] = host.name
            continue
        for rule in directional_rules(intent, kb):
            if kind == SolutionKind.ACL:
                p = acl_placement(kb, rule)
                if not p:
                    raise GenerationError(f"{intent.id}: cannot place ACL for {rule.src} -> {rule.dst}")
                acl_rules[(p.device, p.interface, p.direction)].append((_rule_key(intent, rule), rule))
            else:
                p = firewall_placement(kb, rule)
                if not p:
                    raise GenerationError(f"{intent.id}: no zone boundary for {rule.src} -> {rule.dst}")
                fw_rules[(p.device, p.src_zone, p.dst_zone)].append((_rule_key(intent, rule), rule))

    devices = set(current) | {k[0] for k in acl_rules} | {k[0] for k in fw_rules} | {k[0] for k in isolate}
    default = Action(kb.policies.default_acl_action)
    out: dict[str, DeviceState] = {}
    for dev in sorted(devices):
        cur = current.get(dev, DeviceState())
        rev = cur.revision + 1
        new = DeviceState(revision=rev)

        for (d, iface, direction), items in sorted(acl_rules.items()):
            if d != dev:
                continue
            rules = [r for _, r in sorted(items, key=lambda x: x[0])]
            old_bind = cur.binding(iface, direction)
            old = cur.acl(old_bind.acl) if old_bind else None
            if old and old.rules == rules and old.default_action == default:
                acl = old
            else:
                acl = AccessList(name=f"IBN_{short_if(iface)}_{direction.upper()}_R{rev}", rules=rules,
                                 default_action=default)
            new.acls.append(acl)
            new.bindings.append(AclBinding(interface=iface, direction=direction, acl=acl.name))

        pair_rules = {(sz, dz): [r for _, r in sorted(items, key=lambda x: x[0])]
                      for (d, sz, dz), items in fw_rules.items() if d == dev}
        if pair_rules:
            zones = device_zones(kb, dev)
            names = sorted(set(zones.values()))
            old_pairs = {(z.src_zone, z.dst_zone): z for z in (cur.firewall.zone_pairs if cur.firewall else [])}
            pairs = []
            for sz in names:
                for dz in names:
                    if sz == dz:
                        continue
                    rules = pair_rules.get((sz, dz), [])
                    old = old_pairs.get((sz, dz))
                    if old and old.rules == rules:
                        pairs.append(old)
                        continue
                    tag = f"{sz.removeprefix('IBN_')}_{dz.removeprefix('IBN_')}"
                    pairs.append(ZonePair(name=f"IBN_ZP_{tag}", src_zone=sz, dst_zone=dz,
                                          policy=f"IBN_PM_{tag}_R{rev}", rules=rules))
            new.firewall = FirewallConfig(zones=zones, zone_pairs=pairs)

        _vlan_state(kb, dev, cur, new, {p: h for (sw, p), h in isolate.items() if sw == dev})

        if new.content_equal(cur):
            new.revision = cur.revision
        out[dev] = new
    return out


def _vlan_state(kb: KnowledgeBase, dev: str, cur: DeviceState, new: DeviceState, isolate: dict[str, str]) -> None:
    lo, hi = kb.policies.vlan_range
    used = {v.id for v in cur.vlans} | {i.vlan for i in kb.interfaces.get(dev, {}).values() if i.vlan}
    for port, host in sorted(isolate.items()):
        old_port = next((p for p in cur.access_ports if p.interface == port), None)
        old_vlan = next((v for v in cur.vlans if old_port and v.id == old_port.vlan), None)
        if old_vlan:
            vlan = old_vlan
        else:
            free = next((v for v in range(lo, hi + 1) if v not in used and v not in kb.policies.reserved_vlans), None)
            if free is None:
                raise GenerationError(f"{dev}: no free VLAN in range {lo}-{hi}")
            used.add(free)
            vlan = Vlan(id=free, name=f"IBN_ISOLATE_{host.upper()}")
        new.vlans.append(vlan)
        new.access_ports.append(AccessPort(interface=port, vlan=vlan.id))
    for p in cur.access_ports:  # ports no longer isolated go back to their original VLAN
        if p.interface not in isolate:
            new.access_ports.append(AccessPort(interface=p.interface, vlan=_original_vlan(kb, dev, p.interface)))


def _original_vlan(kb: KnowledgeBase, dev: str, port: str) -> int:
    itf = kb.interface(dev, port)
    return itf.vlan if itf and itf.vlan else 1


def build_candidate(kb: KnowledgeBase, records: list[tuple[Intent, SolutionKind]],
                    current: dict[str, DeviceState], solution: SolutionKind | None) -> CandidateConfig:
    stage_order = kb.policies.deployment.get("stage_order", ["switch", "router"])
    changes = []
    for dev, after in desired_states(kb, records, current).items():
        before = current.get(dev, DeviceState()).model_copy(deep=True)
        for p in after.access_ports:  # make the original VLAN explicit so rollback restores it
            if not any(b.interface == p.interface for b in before.access_ports):
                before.access_ports.append(AccessPort(interface=p.interface, vlan=_original_vlan(kb, dev, p.interface)))
        if before.content_equal(after):
            continue
        platform = kb.devices[dev].platform
        driver = get_driver(platform)
        changes.append(DeviceChange(device=dev, platform=platform, before=before, after=after,
                                    commands=driver.render_transition(before, after),
                                    rollback=driver.render_transition(after, before)))
    role_rank = lambda c: (stage_order.index(kb.devices[c.device].role)  # noqa: E731
                           if kb.devices[c.device].role in stage_order else len(stage_order), c.device)
    return CandidateConfig(solution=solution, changes=sorted(changes, key=role_rank))
