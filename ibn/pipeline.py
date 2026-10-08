"""End-to-end orchestration. The CLI uses this today; a web UI can call the same methods later."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field

from ibn.config import Settings
from ibn.control.audit import AuditLog
from ibn.control.deployer import Deployer, DeploymentReport
from ibn.control.verifier import Probe, plan_probes
from ibn.intent.validation import validate_intents
from ibn.kb.knowledge_base import KnowledgeBase
from ibn.kb.state import IntentRecord, IntentStatus, StateStore
from ibn.models.intent import Intent, SolutionKind
from ibn.models.netconfig import CandidateConfig, DeviceChange, DeviceState
from ibn.models.report import ValidationReport
from ibn.translation.generator import GenerationError, build_candidate
from ibn.translation.selector import rank
from ibn.validation.validator import Validator


class PlanError(Exception):
    pass


class Attempt(BaseModel):
    solution: SolutionKind
    passed: bool
    errors: list[str] = Field(default_factory=list)


class Plan(BaseModel):
    plan_id: str
    kind: Literal["submit", "withdraw"]
    request: str
    created: datetime
    intents: list[Intent] = Field(default_factory=list)
    intent_report: ValidationReport | None = None
    options: list[dict[str, Any]] = Field(default_factory=list)
    attempts: list[Attempt] = Field(default_factory=list)
    chosen: SolutionKind | None = None
    candidate: CandidateConfig | None = None
    validation: ValidationReport | None = None
    probes: list[dict[str, Any]] = Field(default_factory=list)
    state_fingerprint: str = ""

    @computed_field
    @property
    def ok(self) -> bool:
        return self.candidate is not None and self.validation is not None and self.validation.passed


class IBN:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.kb = KnowledgeBase(settings.kb_dir)
        self.store = StateStore(settings.state_dir)
        self.audit = AuditLog(settings.logs_dir / "audit.jsonl")
        self.validator = Validator(self.kb)

    # ---------------------------------------------------------------- planning
    def plan_submit(self, raw_intents: list[dict[str, Any]], request: str,
                    solution: SolutionKind | None = None) -> Plan:
        plan = self._new_plan("submit", request)
        active = self.store.active()
        intents, plan.intent_report = validate_intents(raw_intents, self.kb, active)
        plan.intents = intents
        if not plan.intent_report.passed:
            return self._save(plan)

        options = rank(intents, self.kb)
        plan.options = [vars(o) | {"kind": o.kind.value} for o in options]
        candidates = [o.kind for o in options if o.feasible and (solution is None or o.kind == solution)]
        base = [(r.intent, r.solution) for r in active]
        all_after = [r.intent for r in active] + intents
        for kind in candidates:  # validator feedback loop: fall back to the next-best solution
            ok = self._try(plan, base + [(i, kind) for i in intents], all_after, intents, kind)
            if ok:
                break
        return self._save(plan)

    def plan_withdraw(self, intent_id: str) -> Plan:
        active = self.store.active()
        target = next((r for r in active if r.intent.id == intent_id), None)
        if not target:
            raise PlanError(f"no deployed intent {intent_id}")
        plan = self._new_plan("withdraw", f"withdraw {intent_id}")
        plan.intents = [target.intent]
        rest = [r for r in active if r.intent.id != intent_id]
        self._try(plan, [(r.intent, r.solution) for r in rest], [r.intent for r in rest], [target.intent],
                  target.solution)
        return self._save(plan)

    def _try(self, plan: Plan, records, active_after: list[Intent], changed: list[Intent],
             kind: SolutionKind) -> bool:
        current = self.store.managed()
        try:
            candidate = build_candidate(self.kb, records, current, kind)
        except GenerationError as exc:
            plan.attempts.append(Attempt(solution=kind, passed=False, errors=[str(exc)]))
            return False
        report = self.validator.validate(candidate, current, active_after, changed,
                                         title=f"Validation report – {plan.plan_id} ({kind.value})")
        plan.attempts.append(Attempt(solution=kind, passed=report.passed, errors=[str(e) for e in report.errors()]))
        plan.candidate, plan.validation, plan.chosen = candidate, report, kind
        if report.passed:
            after = {**current, **{c.device: c.after for c in candidate.changes}}
            plan.probes = [vars(p) for p in plan_probes(self.kb, current, after)]
        return report.passed

    def _new_plan(self, kind: str, request: str) -> Plan:
        now = datetime.now(timezone.utc)
        return Plan(plan_id=f"plan-{now:%Y%m%d-%H%M%S}-{uuid4().hex[:4]}", kind=kind, request=request,
                    created=now, state_fingerprint=self.store.fingerprint())

    # ---------------------------------------------------------------- packages
    def package_dir(self, plan_id: str) -> Path:
        return self.settings.artifacts_dir / plan_id

    def _save(self, plan: Plan) -> Plan:
        d = self.package_dir(plan.plan_id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "plan.json").write_text(plan.model_dump_json(indent=2))
        if plan.intent_report:
            (d / "intent_validation.md").write_text(plan.intent_report.to_markdown())
        if plan.validation:
            (d / "validation_report.md").write_text(plan.validation.to_markdown())
        if plan.candidate:
            for ch in plan.candidate.changes:
                for sub, lines in (("configs", ch.commands), ("rollback", ch.rollback)):
                    (d / sub).mkdir(exist_ok=True)
                    (d / sub / f"{ch.device}.txt").write_text("\n".join(lines) + "\n")
        self.audit.write("plan", plan=plan.plan_id, kind=plan.kind, ok=plan.ok,
                         intents=[i.summary() for i in plan.intents], solution=plan.chosen)
        return plan

    def load_plan(self, plan_id: str) -> Plan:
        path = self.package_dir(plan_id) / "plan.json"
        if not path.is_file():
            raise PlanError(f"unknown plan {plan_id}")
        return Plan.model_validate_json(path.read_text())

    # ---------------------------------------------------------------- deployment
    def deploy(self, plan_id: str, *, dry_run: bool = True, record_state: bool = False) -> DeploymentReport:
        plan = self.load_plan(plan_id)
        if not plan.ok:
            raise PlanError(f"{plan_id} did not pass validation; refusing to deploy")
        if plan.state_fingerprint != self.store.fingerprint():
            raise PlanError("network state changed since this plan was made; re-plan it")
        policy = self.kb.policies.deployment
        report = self._deployer().deploy(plan_id, plan.candidate, [Probe(**p) for p in plan.probes],
                                         dry_run=dry_run, auto_rollback=policy.get("auto_rollback", True),
                                         save=policy.get("save_config", False))
        if report.success and (not dry_run or record_state):
            self._commit_state(plan, report)
        (self.package_dir(plan_id) / f"{report.deployment_id}.json").write_text(report.model_dump_json(indent=2))
        return report

    def _commit_state(self, plan: Plan, report: DeploymentReport) -> None:
        records, managed = self.store.records(), self.store.managed()
        (self.package_dir(plan.plan_id) / "state_before.json").write_text(json.dumps({
            "records": [r.model_dump(mode="json") for r in records],
            "managed": {k: v.model_dump(mode="json") for k, v in managed.items()},
        }, indent=2))
        now = datetime.now(timezone.utc)
        if plan.kind == "submit":
            records += [IntentRecord(intent=i, solution=plan.chosen, plan_id=plan.plan_id, updated_at=now)
                        for i in plan.intents]
        else:
            withdrawn = {i.id for i in plan.intents}
            for r in records:
                if r.intent.id in withdrawn:
                    r.status, r.updated_at = IntentStatus.WITHDRAWN, now
        for ch in plan.candidate.changes:
            managed[ch.device] = ch.after
        self.store.save(records, managed)
        (self.package_dir(plan.plan_id) / "state_after.fingerprint").write_text(self.store.fingerprint())

    def rollback(self, plan_id: str, *, dry_run: bool = True, record_state: bool = False) -> DeploymentReport:
        """Undo the most recent committed plan using its stored rollback commands and prior state."""
        plan = self.load_plan(plan_id)
        d = self.package_dir(plan_id)
        fp, before = d / "state_after.fingerprint", d / "state_before.json"
        if not fp.is_file() or not before.is_file():
            raise PlanError(f"{plan_id} was never committed")
        if fp.read_text() != self.store.fingerprint():
            raise PlanError("other changes were committed after this plan; withdraw intents instead")
        reverse = CandidateConfig(solution=plan.chosen, changes=[
            DeviceChange(device=c.device, platform=c.platform, before=c.after, after=c.before,
                         commands=c.rollback, rollback=c.commands) for c in reversed(plan.candidate.changes)])
        report = self._deployer().deploy(f"{plan_id}-rollback", reverse, [], dry_run=dry_run,
                                         auto_rollback=True, save=self.kb.policies.deployment.get("save_config", False))
        if report.success and (not dry_run or record_state):
            state = json.loads(before.read_text())
            self.store.save([IntentRecord.model_validate(r) for r in state["records"]],
                            {k: DeviceState.model_validate(v) for k, v in state["managed"].items()})
            fp.unlink()
        return report

    def _deployer(self) -> Deployer:
        return Deployer(self.kb, self.settings.backups_dir, self.audit)
