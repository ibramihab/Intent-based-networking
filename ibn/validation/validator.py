"""Validator: syntax, semantic, intent compliance, impact analysis and simulation.

A failing report sends the pipeline back to the Config Generator with the next-best solution.
"""

from __future__ import annotations

import re
from itertools import permutations

from ibn.intent.space import TrafficSpace, spaces, specificity
from ibn.kb.knowledge_base import KnowledgeBase, find_ip_conflicts
from ibn.models.intent import Action, Intent, Protocol, Service
from ibn.models.netconfig import CandidateConfig, DeviceState
from ibn.models.report import StageResult, ValidationReport, error, info, warning
from ibn.translation.drivers import get_driver
from ibn.validation.batfish import batfish_stage
from ibn.validation.simulator import Flow, Simulator


def probe_flows(space: TrafficSpace, kb: KnowledgeBase) -> list[Flow]:
    src, dst = kb.representative_ip(space.src), kb.representative_ip(space.dst)
    if space.ports:
        return [Flow(src, dst, space.protocol, p) for p in sorted(space.ports)]
    if space.protocol == Protocol.IP:
        return [Flow(src, dst, Protocol.ICMP), Flow(src, dst, Protocol.TCP, 443)]
    sample = {Protocol.TCP: 80, Protocol.UDP: 53}.get(space.protocol)
    return [Flow(src, dst, space.protocol, sample)]


def intended(flow: Flow, intents: list[Intent], kb: KnowledgeBase) -> tuple[Action, Intent] | None:
    """The action the intent model prescribes for a flow (same precedence as the generator)."""
    best = None
    for it in intents:
        for sp in spaces(it, kb):
            if sp.matches(flow.src, flow.dst, flow.protocol, flow.port):
                key = (it.priority, specificity(sp))
                if best is None or key > best[0]:
                    best = (key, it)
    return (best[1].action, best[1]) if best else None


class Validator:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def validate(self, candidate: CandidateConfig, current: dict[str, DeviceState], active_after: list[Intent],
                 changed: list[Intent], title: str) -> ValidationReport:
        report = ValidationReport(title=title)
        after = {**current, **{c.device: c.after for c in candidate.changes}}
        report.add(self.syntax(candidate))
        report.add(self.semantic(candidate))
        report.add(self.compliance(after, active_after))
        report.add(self.impact(current, after, changed))
        report.add(batfish_stage(self.kb, candidate))
        return report

    # ---------------------------------------------------------------- syntax
    def syntax(self, candidate: CandidateConfig) -> StageResult:
        stage = StageResult(name="Syntax")
        for ch in candidate.changes:
            driver = get_driver(ch.platform)
            for label, cmds in (("config", ch.commands), ("rollback", ch.rollback)):
                for issue in driver.validate_syntax(cmds):
                    issue.device = ch.device
                    issue.message = f"{label} {issue.message}"
                    stage.issues.append(issue)
        stage.details["lines"] = {c.device: len(c.commands) for c in candidate.changes}
        return stage

    # ---------------------------------------------------------------- semantic
    def semantic(self, candidate: CandidateConfig) -> StageResult:
        stage = StageResult(name="Semantic")
        kb = self.kb
        stage.issues += find_ip_conflicts(kb.all_l3_interfaces())
        for ch in candidate.changes:
            dev, a = ch.device, ch.after
            caps = kb.devices[dev].capabilities
            known = kb.interfaces.get(dev, {})
            used_ifaces = [b.interface for b in a.bindings] + [p.interface for p in a.access_ports]
            used_ifaces += list(a.firewall.zones) if a.firewall else []
            for iface in used_ifaces:
                if iface not in known:
                    stage.issues.append(error(f"interface {iface} does not exist", dev))
            acl_names = {x.name for x in a.acls}
            for b in a.bindings:
                if b.acl not in acl_names:
                    stage.issues.append(error(f"{b.interface} references undefined ACL {b.acl}", dev))
                if "acl" not in caps:
                    stage.issues.append(error("device does not support ACLs", dev))
            if a.firewall:
                if "zbf" not in caps:
                    stage.issues.append(error("device does not support zone-based firewall", dev))
                zones = set(a.firewall.zones.values())
                for zp in a.firewall.zone_pairs:
                    for z in (zp.src_zone, zp.dst_zone):
                        if z not in zones:
                            stage.issues.append(error(f"zone-pair {zp.name} references missing zone {z}", dev))
                routed = {i.name for i in kb.l3_interfaces(dev)}
                if unzoned := routed - set(a.firewall.zones):
                    stage.issues.append(error(f"routed interfaces left out of all zones: {sorted(unzoned)}", dev))
            lo, hi = kb.policies.vlan_range
            new_vlans = {v.id for v in a.vlans} - {v.id for v in ch.before.vlans}
            existing = {i.vlan for i in known.values() if i.vlan}
            for vid in new_vlans:
                if vid in kb.policies.reserved_vlans:
                    stage.issues.append(error(f"VLAN {vid} is reserved", dev))
                elif not lo <= vid <= hi:
                    stage.issues.append(warning(f"VLAN {vid} outside allowed range {lo}-{hi}", dev))
                if vid in existing:
                    stage.issues.append(error(f"VLAN ID collision: {vid} already in use", dev))
            if a.vlans and "vlan" not in caps:
                stage.issues.append(error("device does not support VLAN changes", dev))
            stage.issues += self._running_config_conflicts(dev, ch.before, a)
        return stage

    def _running_config_conflicts(self, dev: str, before: DeviceState, after: DeviceState):
        running = self.kb.running_config(dev)
        if running is None:
            return [info("running config not synced; collision checks against live config skipped", dev)]
        issues = []
        managed = {x.name for x in before.acls} | {x.name for x in after.acls}
        for acl in after.acls:
            if acl.name not in {x.name for x in before.acls} and re.search(
                    rf"^ip access-list extended {re.escape(acl.name)}$", running, re.M):
                issues.append(error(f"ACL name {acl.name} already exists on the device", dev))
        for b in after.bindings:
            block = re.search(rf"^interface {re.escape(b.interface)}\n((?: .*\n?)*)", running, re.M)
            for m in re.finditer(rf"ip access-group (\S+) {b.direction}", block.group(1) if block else ""):
                if m.group(1) not in managed:
                    issues.append(error(f"{b.interface} already has unmanaged ACL {m.group(1)} {b.direction}", dev))
        for vid in {v.id for v in after.vlans} - {v.id for v in before.vlans}:
            if re.search(rf"^vlan {vid}$", running, re.M):
                issues.append(error(f"VLAN ID collision: {vid} exists in running config", dev))
        return issues

    # ---------------------------------------------------------------- compliance
    def compliance(self, after: dict[str, DeviceState], intents: list[Intent]) -> StageResult:
        stage = StageResult(name="Intent compliance (simulated)")
        sim = Simulator(self.kb, after)
        results = []
        for it in intents:
            for sp in spaces(it, self.kb):
                for flow in probe_flows(sp, self.kb):
                    verdict = sim.evaluate(flow)
                    want, owner = intended(flow, intents, self.kb)
                    ok = verdict.allowed == (want == Action.PERMIT)
                    results.append({"intent": it.id, "flow": str(flow), "allowed": verdict.allowed, "ok": ok})
                    if not ok:
                        stage.issues.append(error(f"{it.id}: {flow} expected {want.value}, simulated "
                                                  f"{'permit' if verdict.allowed else 'deny'}: "
                                                  + " | ".join(verdict.trace)))
                    elif owner.id != it.id:
                        stage.issues.append(info(f"{it.id}: {flow} is governed by higher-precedence {owner.id}"))
        stage.details["probes"] = results
        return stage

    # ---------------------------------------------------------------- impact
    def impact(self, before: dict[str, DeviceState], after: dict[str, DeviceState],
               changed: list[Intent]) -> StageResult:
        stage = StageResult(name="Impact analysis")
        kb = self.kb
        endpoints = sorted({str(h.ip) for h in kb.hosts.values()}
                           | {kb.representative_ip(g.subnet) for g in kb.groups.values()}
                           | {str(i.ip.ip) for i in kb.all_l3_interfaces()})
        services = kb.policies.probe_services()
        for it in changed:
            services += [s for s in it.services if s.protocol != Protocol.IP]
        flows = [f for a, b in permutations(endpoints, 2) for f in _flows(a, b, services)]
        sim_b, sim_a = Simulator(kb, before), Simulator(kb, after)
        changed_spaces = [sp for it in changed for sp in spaces(it, kb)]
        diffs, unexpected = [], 0
        for flow in flows:
            was, now = sim_b.evaluate(flow).allowed, sim_a.evaluate(flow).allowed
            if was == now:
                continue
            explained = any(sp.matches(flow.src, flow.dst, flow.protocol, flow.port) for sp in changed_spaces)
            change = f"{flow}: {'permit' if was else 'deny'} -> {'permit' if now else 'deny'}"
            diffs.append({"flow": str(flow), "before": was, "after": now, "explained": explained})
            if kb.is_protected(flow.src) and kb.is_protected(flow.dst):
                stage.issues.append(error(f"guardrail: infrastructure traffic affected: {change}"))
            elif not explained:
                unexpected += 1
                stage.issues.append(warning(f"collateral change not requested by any intent: {change}"))
        stage.issues.insert(0, info(f"{len(flows)} flows simulated, {len(diffs)} changed "
                                    f"({len(diffs) - unexpected} intended, {unexpected} collateral)"))
        stage.details["changed_flows"] = diffs
        return stage


def _flows(src: str, dst: str, services: list[Service]) -> list[Flow]:
    out = set()
    for s in services:
        for p in s.ports or [None]:
            out.add(Flow(src, dst, s.protocol, p))
    return sorted(out, key=str)
