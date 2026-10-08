"""Validation Layer: checks ANY configuration the Intent Layer produced, whatever technique it used.

Stages
  1. Design structure   devices exist, platform supported, rollback present, verify commands read-only
  2. Syntax             platform grammar + forbidden commands (guardrails)
  3. Semantic           config applied to IBN's view of each device: interfaces exist, IP overlap,
                        VLAN collisions, missing/dangling references, protected interfaces, naming
  4. Rollback           applying commands then rollback must restore the original config
  5. Intent compliance  every expectation (new and already deployed) simulated on the result
  6. Impact analysis    all endpoint pairs simulated before/after; unexplained changes are collateral
  7. AI review          an independent LLM review of the change
  8. Batfish            optional high-fidelity simulation
Errors are fed back to the Intent Layer, which redesigns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import permutations
from typing import Any, Callable

from ibn.intent.space import FlowSpace, intended, sample_flows, spaces
from ibn.kb.knowledge_base import KBError, KnowledgeBase
from ibn.models.dataplane import Flow
from ibn.models.design import ConfigDesign
from ibn.models.intent import Intent
from ibn.models.report import StageResult, ValidationReport, error, info, warning
from ibn.platforms import get_platform
from ibn.platforms.configtree import ConfigTree, diff
from ibn.validation.batfish import batfish_stage
from ibn.validation.simulator import Simulator, build_models

Reviewer = Callable[[ConfigDesign], dict[str, Any]]


@dataclass
class ValidationContext:
    configs: dict[str, str]  # IBN's view of every device before the change
    active_after: list[Intent]  # intents whose expectations must hold after the change
    changed: list[Intent]  # intents being added or withdrawn: they explain traffic changes
    reviewer: Reviewer | None = None


@dataclass
class ValidationResult:
    report: ValidationReport
    after: dict[str, str] = field(default_factory=dict)
    limited: list[str] = field(default_factory=list)  # why verification is limited


class Validator:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def validate(self, design: ConfigDesign, ctx: ValidationContext, title: str) -> ValidationResult:
        rep = ValidationReport(title=title)
        res = ValidationResult(report=rep)
        structure = rep.add(self.structure(design))
        syntax = rep.add(self.syntax(design))
        if not (structure.passed and syntax.passed):
            return res  # cannot safely interpret the config any further
        before_trees = {d: get_platform(self.kb.devices[d].platform).parse(t) for d, t in ctx.configs.items()}
        after_trees = dict(before_trees)
        for dc in design.devices:
            after_trees[dc.device] = get_platform(self.kb.devices[dc.device].platform).apply(
                before_trees[dc.device], dc.commands)
        res.after = {d: t.render() + "\n" for d, t in after_trees.items()}

        rep.add(self.semantic(design, before_trees, after_trees))
        rep.add(self.rollback(design, before_trees, after_trees))
        for dc in design.devices:
            platform = get_platform(self.kb.devices[dc.device].platform)
            res.limited += [f"{dc.device}: {n}" for n in platform.unmodeled(dc.commands)]
        before_models, after_models = build_models(self.kb, before_trees), build_models(self.kb, after_trees)
        rep.add(self.compliance(after_models, ctx, res.limited))
        rep.add(self.impact(before_models, after_models, ctx, design, before_trees, after_trees))
        rep.add(self.review(design, ctx))
        rep.add(batfish_stage(self.kb, res.after))
        return res

    # ---------------------------------------------------------------- 1. structure
    def structure(self, design: ConfigDesign) -> StageResult:
        st = StageResult(name="Design structure")
        if not any(d.commands for d in design.devices):
            st.issues.append(error("the design contains no configuration commands"))
        seen = set()
        for dc in design.devices:
            if dc.device in seen:
                st.issues.append(error(f"device {dc.device} appears twice; merge its commands"))
            seen.add(dc.device)
            dev = self.kb.devices.get(dc.device)
            if dev is None:
                st.issues.append(error(f"unknown device {dc.device} (inventory: {', '.join(self.kb.devices)})"))
                continue
            try:
                platform = get_platform(dev.platform)
            except KeyError as exc:
                st.issues.append(error(str(exc), dc.device))
                continue
            if dc.commands and not dc.rollback:
                st.issues.append(error("no rollback commands for this device", dc.device))
            if dc.commands and not dc.verify:
                st.issues.append(warning("no verification commands; only command errors will be checked", dc.device))
            for chk in dc.verify:
                if not platform.is_read_only(chk.command):
                    st.issues.append(error(f"verify command is not read-only: '{chk.command}'", dc.device))
        model_devices = {str(m.get("device")) for m in design.neutral_model if m.get("device")}
        if missing := model_devices - seen:
            st.issues.append(warning(f"neutral model mentions {sorted(missing)} but no config was generated for them"))
        if not design.neutral_model:
            st.issues.append(warning("the design has no vendor-neutral model"))
        return st

    # ---------------------------------------------------------------- 2. syntax
    def syntax(self, design: ConfigDesign) -> StageResult:
        st = StageResult(name="Syntax")
        for dc in design.devices:
            if dc.device not in self.kb.devices:
                continue
            platform = get_platform(self.kb.devices[dc.device].platform)
            for label, lines in (("config", dc.commands), ("rollback", dc.rollback)):
                for issue in platform.syntax_check(lines):
                    issue.device, issue.message = dc.device, f"{label} {issue.message}"
                    st.issues.append(issue)
                for n, line in enumerate(lines, 1):
                    for rx, reason in self.kb.policies.forbidden_commands:
                        if rx.search(line):
                            st.issues.append(error(f"{label} line {n} '{line.strip()}': forbidden ({reason})", dc.device))
        return st

    # ---------------------------------------------------------------- 3. semantic
    def semantic(self, design: ConfigDesign, before: dict[str, ConfigTree], after: dict[str, ConfigTree]) -> StageResult:
        st = StageResult(name="Semantic")
        kb = self.kb
        prefix = kb.policies.object_prefix
        for dc in design.devices:
            dev = dc.device
            platform = get_platform(kb.devices[dev].platform)
            b_ifaces, a_ifaces = platform.interface_commands(before[dev]), platform.interface_commands(after[dev])
            known = set(kb.interfaces.get(dev, {})) | set(b_ifaces)
            for name in set(a_ifaces) - set(b_ifaces):
                if name.startswith(("Loopback", "Tunnel", "Vlan", "Port-channel", "BDI", "Dialer", "NVI")) or "." in name:
                    st.issues.append(info(f"creates logical interface {name}", dev))
                elif name not in known:
                    st.issues.append(error(f"interface {name} does not exist on this device", dev))

            b_defs, b_refs = platform.references(before[dev])
            a_defs, a_refs = platform.references(after[dev])
            a_defs |= {("interface", i) for i in kb.interfaces.get(dev, {})}
            old_refs = {(r.kind, r.name) for r in b_refs}
            for r in a_refs:
                if (r.kind, r.name) not in a_defs:
                    msg = f"{r.kind} '{r.name}' is referenced ({r.where}) but not defined"
                    if (r.kind, r.name) in b_defs:
                        st.issues.append(error(f"{msg}: the change deletes it while it is still in use", dev))
                    elif (r.kind, r.name) not in old_refs:
                        st.issues.append(error(msg, dev))
            for kind, name in sorted(a_defs - b_defs):
                if kind != "interface" and not name.isdigit() and not name.startswith(prefix):
                    st.issues.append(warning(f"new {kind} '{name}' does not use the '{prefix}' prefix", dev))

            mgmt = kb.devices[dev].mgmt.interface
            if mgmt and a_ifaces.get(mgmt) != b_ifaces.get(mgmt):
                st.issues.append(error(f"changes the management interface {mgmt}; IBN could lose access", dev))
            for name, cmds in a_ifaces.items():
                was = b_ifaces.get(name, [])
                if "shutdown" in cmds and "shutdown" not in was:
                    itf = kb.interface(dev, name)
                    if itf and itf.ip and kb.is_protected(str(itf.ip.ip)):
                        st.issues.append(error(f"shuts down infrastructure interface {name}", dev))
                    else:
                        st.issues.append(warning(f"shuts down interface {name}", dev))
                old_ip = next((c for c in was if c.startswith("ip address ")), None)
                new_ip = next((c for c in cmds if c.startswith("ip address ")), None)
                if old_ip and new_ip and old_ip != new_ip:
                    st.issues.append(warning(f"changes the address of {name}: '{old_ip}' -> '{new_ip}'", dev))

        models = build_models(kb, after)
        ifaces = [(d, i) for d, m in models.items() for i in m.interfaces.values() if i.ip]
        for idx, (da, a) in enumerate(ifaces):
            for db, b in ifaces[idx + 1:]:
                if a.ip.ip == b.ip.ip:
                    st.issues.append(error(f"duplicate IP {a.ip.ip} on {da} {a.name} and {db} {b.name}"))
                elif a.ip.network != b.ip.network and a.ip.network.overlaps(b.ip.network):
                    st.issues.append(error(f"IP overlap: {da} {a.name} {a.ip.network} vs {db} {b.name} {b.ip.network}"))
                elif a.ip.network == b.ip.network and not self._linked(da, a.name, db, b.name):
                    st.issues.append(error(f"subnet {a.ip.network} is used on both {da} {a.name} and {db} {b.name}, "
                                           "which are not connected"))
        for h in kb.hosts.values():
            for d, i in ifaces:
                if i.ip.ip == h.ip:
                    st.issues.append(error(f"{d} {i.name} uses {h.ip}, which belongs to host {h.name}"))

        lo, hi = kb.policies.vlan_range
        before_models = build_models(kb, before)
        for dc in design.devices:
            new_vlans = models[dc.device].vlans - before_models[dc.device].vlans
            for vid in sorted(new_vlans):
                if vid in kb.policies.reserved_vlans:
                    st.issues.append(error(f"VLAN {vid} is reserved", dc.device))
                elif not lo <= vid <= hi:
                    st.issues.append(warning(f"VLAN {vid} is outside the allowed range {lo}-{hi}", dc.device))
            in_use = {i.vlan for i in kb.interfaces.get(dc.device, {}).values() if i.vlan}
            for vid in sorted(new_vlans & in_use - {1}):
                st.issues.append(error(f"VLAN ID collision: {vid} is already used on this switch", dc.device))
            for itf in models[dc.device].interfaces.values():
                if itf.access_vlan != 1 and itf.access_vlan not in models[dc.device].vlans:
                    st.issues.append(warning(f"{itf.name} uses VLAN {itf.access_vlan}, which is not defined "
                                             "(IOS creates it implicitly)", dc.device))
        return st

    # ---------------------------------------------------------------- 4. rollback
    def rollback(self, design: ConfigDesign, before: dict[str, ConfigTree], after: dict[str, ConfigTree]) -> StageResult:
        st = StageResult(name="Rollback check")
        for dc in design.devices:
            restored = get_platform(self.kb.devices[dc.device].platform).apply(after[dc.device], dc.rollback)
            extra, missing = diff(before[dc.device], restored)
            if extra or missing:
                lines = [f"left behind: {x}" for x in extra[:4]] + [f"not restored: {x}" for x in missing[:4]]
                st.issues.append(error("rollback does not restore the original config: " + "; ".join(lines), dc.device))
            added, removed = diff(before[dc.device], after[dc.device])
            st.details[dc.device] = {"added": added, "removed": removed}
            if not added and not removed:
                st.issues.append(warning("the commands do not change this device's configuration", dc.device))
        return st

    # ---------------------------------------------------------------- 5. compliance
    def compliance(self, after_models, ctx: ValidationContext, limited: list[str]) -> StageResult:
        st = StageResult(name="Intent compliance (simulated)")
        sim = Simulator(self.kb, after_models)
        all_spaces = self._spaces(ctx.active_after)
        probes = []
        for sp in all_spaces:
            for flow in sample_flows(sp, self.kb):
                verdict = sim.evaluate(flow)
                owner = intended(flow, all_spaces)
                ok = verdict.allowed == owner.allow
                probes.append({"intent": sp.intent_id, "expectation": sp.label, "flow": str(flow),
                               "allowed": verdict.allowed, "ok": ok})
                if ok:
                    if owner.intent_id != sp.intent_id:
                        st.issues.append(info(f"{sp.intent_id}: {flow} is governed by higher-precedence {owner.intent_id}"))
                    continue
                msg = (f"{sp.intent_id} '{owner.label}': {flow} should be {'allowed' if owner.allow else 'denied'}, "
                       f"simulation says {'allowed' if verdict.allowed else 'denied'} | " + " | ".join(verdict.trace))
                st.issues.append(warning(msg + " (unconfirmed: the change uses features the simulator does not model)")
                                 if limited else error(msg))
        if limited:
            st.issues.append(warning("limited verification - not simulated: " + "; ".join(limited)))
        if not all_spaces:
            st.issues.append(warning("no expectations to simulate"))
        st.details["probes"] = probes
        return st

    # ---------------------------------------------------------------- 6. impact
    def impact(self, before_models, after_models, ctx: ValidationContext, design: ConfigDesign,
               before: dict[str, ConfigTree], after: dict[str, ConfigTree]) -> StageResult:
        st = StageResult(name="Impact analysis")
        kb = self.kb
        endpoints = sorted({str(h.ip) for h in kb.hosts.values()}
                           | {kb.representative_ip(g.subnet) for g in kb.groups.values()}
                           | {str(i.ip.ip) for m in after_models.values() for i in m.l3_interfaces()})
        services = list(kb.policies.probe_services())
        changed_spaces = self._spaces(ctx.changed)
        services += [(s.protocol, s.port) for s in changed_spaces if s.protocol != "any"]
        services = sorted(set(services), key=str)
        sim_b, sim_a = Simulator(kb, before_models), Simulator(kb, after_models)
        diffs, collateral = [], 0
        for a, b in permutations(endpoints, 2):
            for proto, port in services:
                flow = Flow(a, b, proto, port)
                was, now = sim_b.evaluate(flow).allowed, sim_a.evaluate(flow).allowed
                if was == now:
                    continue
                explained = any(sp.matches(flow) for sp in changed_spaces)
                diffs.append({"flow": str(flow), "before": was, "after": now, "explained": explained})
                change = f"{flow}: {'allowed' if was else 'denied'} -> {'allowed' if now else 'denied'}"
                if kb.is_protected(a) and kb.is_protected(b):
                    st.issues.append(error(f"guardrail: infrastructure traffic changes: {change}"))
                elif not explained:
                    collateral += 1
                    st.issues.append(warning(f"collateral change not covered by any intent: {change}"))
        devices = ", ".join(f"{d.device} (+{len(diff(before[d.device], after[d.device])[0])}"
                            f"/-{len(diff(before[d.device], after[d.device])[1])} lines)" for d in design.devices)
        st.issues.insert(0, info(f"devices changed: {devices or 'none'}; {len(diffs)} simulated flows change "
                                 f"({len(diffs) - collateral} intended, {collateral} collateral)"))
        st.details["changed_flows"] = diffs
        return st

    # ---------------------------------------------------------------- 7. AI review
    def review(self, design: ConfigDesign, ctx: ValidationContext) -> StageResult:
        st = StageResult(name="AI review (independent)")
        if ctx.reviewer is None:
            st.skipped = True
            st.issues.append(info("skipped: no AI reviewer available"))
            return st
        try:
            result = ctx.reviewer(design)
        except Exception as exc:  # the review is advisory infrastructure: never crash validation
            st.issues.append(warning(f"AI review failed: {exc}"))
            return st
        blocking = self.kb.policies.llm_review_blocking
        for f in result.get("findings") or []:
            sev = str(f.get("severity", "info")).lower()
            msg, dev = str(f.get("message", "")), f.get("device") or None
            if sev == "error":
                st.issues.append(error(msg, dev) if blocking else warning(msg, dev))
            elif sev == "warning":
                st.issues.append(warning(msg, dev))
            else:
                st.issues.append(info(msg, dev))
        st.details["verdict"] = result.get("verdict", "?")
        st.issues.insert(0, info(f"reviewer verdict: {st.details['verdict']}"))
        return st

    def _linked(self, da: str, ia: str, db: str, ib: str) -> bool:
        """Same subnet on two devices is only valid on a real link (or a tunnel known to the topology)."""
        if da == db:
            return False
        ends = {(da, ia), (db, ib)}
        if any({a, b} == ends for a, b in self.kb.links):
            return True
        ka, kb_ = self.kb.interface(da, ia), self.kb.interface(db, ib)
        return bool(ka and kb_ and ka.ip and kb_.ip and ka.ip.network == kb_.ip.network)

    def _spaces(self, intents: list[Intent]) -> list[FlowSpace]:
        out = []
        for it in intents:
            try:
                out += spaces(it, self.kb)
            except KBError:
                pass
        return out
