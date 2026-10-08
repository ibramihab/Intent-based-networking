"""End-to-end orchestration used by the web interface.

Intent Layer (AI: understand -> validated intent -> design) -> Validation Layer (generic checks)
-> rejected? errors back to the AI, which redesigns -> approval -> Control Layer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError, computed_field

from ibn.config import Settings
from ibn.control.audit import AuditLog
from ibn.control.deployer import Deployer, DeploymentReport
from ibn.control.verifier import Probe, plan_probes
from ibn.intent.agent import IntentAgent
from ibn.intent.llm import LLMError
from ibn.intent.validation import validate_intents
from ibn.kb.knowledge_base import KnowledgeBase
from ibn.kb.state import IntentRecord, IntentStatus, StateStore
from ibn.models.design import ConfigDesign, DeviceConfig
from ibn.models.intent import Intent
from ibn.models.report import ValidationReport
from ibn.validation.simulator import build_models
from ibn.validation.validator import ValidationContext, Validator


class PlanError(Exception):
    pass


class Attempt(BaseModel):
    number: int
    approach: str
    errors: list[str] = Field(default_factory=list)


class Plan(BaseModel):
    plan_id: str
    kind: Literal["submit", "withdraw"]
    request: str
    created: datetime
    intents: list[Intent] = Field(default_factory=list)
    intent_report: ValidationReport | None = None
    design: ConfigDesign | None = None
    design_error: str | None = None
    validation: ValidationReport | None = None
    limited_verification: list[str] = Field(default_factory=list)
    attempts: list[Attempt] = Field(default_factory=list)
    probes: list[dict[str, Any]] = Field(default_factory=list)
    configs_after: dict[str, str] = Field(default_factory=dict)
    state_fingerprint: str = ""

    @computed_field
    @property
    def ok(self) -> bool:
        return (self.design is not None and self.design_error is None
                and self.validation is not None and self.validation.passed)


class IBN:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.kb = KnowledgeBase(settings.kb_dir)
        self.store = StateStore(settings.state_dir)
        self.audit = AuditLog(settings.logs_dir / "audit.jsonl")
        self.validator = Validator(self.kb)

    def configs(self) -> dict[str, str]:
        return self.store.configs(self.kb)

    # ---------------------------------------------------------------- planning
    def plan_submit(self, raw_intents: list[dict[str, Any]], request: str, agent: IntentAgent | None,
                    allow_override: bool = False) -> Plan:
        plan = self._new_plan("submit", request)
        active = self.store.active()
        plan.intents, plan.intent_report = validate_intents(raw_intents, self.kb, active, allow_override)
        if not plan.intent_report.passed:
            return self._save(plan)
        if agent is None:
            plan.design_error = "the AI designer is not available (set GEMINI_API_KEY)"
            return self._save(plan)
        configs = self.configs()
        self._design_loop(plan, agent, lambda: agent.design(plan.intents, configs, active),
                          active_after=[r.intent for r in active] + plan.intents, changed=plan.intents)
        return self._save(plan)

    def plan_withdraw(self, intent_id: str, agent: IntentAgent | None) -> Plan:
        active = self.store.active()
        target = next((r for r in active if r.intent.id == intent_id), None)
        if not target:
            raise PlanError(f"no deployed intent {intent_id}")
        plan = self._new_plan("withdraw", f"withdraw {intent_id}")
        plan.intents = [target.intent]
        rest = [r for r in active if r.intent.id != intent_id]
        if agent is not None:
            configs = self.configs()
            first = lambda: agent.withdraw(target, configs, active)  # noqa: E731
        else:  # no AI: replay the rollback recorded when the intent was deployed
            first = lambda: ConfigDesign(  # noqa: E731
                approach=f"stored rollback of {target.plan_id}",
                reasoning="No AI available: the rollback commands recorded at deployment are replayed.",
                devices=[DeviceConfig(device=d.device, commands=d.rollback, rollback=d.commands)
                         for d in target.devices if d.rollback]).model_dump()
        self._design_loop(plan, agent, first, active_after=[r.intent for r in rest], changed=[target.intent])
        return self._save(plan)

    def _design_loop(self, plan: Plan, agent: IntentAgent | None, first: Callable[[], dict[str, Any]],
                     active_after: list[Intent], changed: list[Intent]) -> None:
        configs = self.configs()
        reviewer = (lambda d: agent.review(plan.intents, d, configs)) if agent else None
        try:
            raw = first()
        except LLMError as exc:
            plan.design_error = str(exc)
            return
        attempts = max(1, self.kb.policies.max_design_attempts)
        for number in range(1, attempts + 1):
            try:
                design = ConfigDesign.model_validate(raw)
            except ValidationError as exc:
                design = None
                errors = [f"design JSON {'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()]
            if design is not None:
                result = self.validator.validate(design, ValidationContext(configs, active_after, changed, reviewer),
                                                 title=f"Validation report – {plan.plan_id} (attempt {number})")
                plan.design, plan.validation = design, result.report
                plan.limited_verification, plan.configs_after = result.limited, result.after
                errors = [str(i) for i in result.report.errors()]
            plan.attempts.append(Attempt(number=number, approach=design.approach if design else "(invalid JSON)",
                                         errors=errors))
            plan.design_error = None if design else "the AI returned a design that does not match the schema"
            if not errors or agent is None or number == attempts:
                break
            try:
                raw = agent.redesign(errors)
            except LLMError as exc:
                plan.design_error = str(exc)
                return
        if plan.ok:
            before, after = build_models(self.kb, configs), build_models(self.kb, plan.configs_after)
            plan.probes = [vars(p) for p in plan_probes(self.kb, before, after)]

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
        if plan.design:
            for dc in plan.design.devices:
                for sub, lines in (("configs", dc.commands), ("rollback", dc.rollback)):
                    (d / sub).mkdir(exist_ok=True)
                    (d / sub / f"{dc.device}.txt").write_text("\n".join(lines) + "\n")
        self.audit.write("plan", plan=plan.plan_id, kind=plan.kind, ok=plan.ok,
                         intents=[i.summary() for i in plan.intents],
                         approach=plan.design.approach if plan.design else None, attempts=len(plan.attempts))
        return plan

    def load_plan(self, plan_id: str) -> Plan:
        path = self.package_dir(plan_id) / "plan.json"
        if not path.is_file():
            raise PlanError(f"unknown plan {plan_id}")
        return Plan.model_validate_json(path.read_text())

    def feedback(self, plan: Plan) -> list[str]:
        return plan.attempts[-1].errors if plan.attempts else []

    def ordered(self, devices: list[DeviceConfig]) -> list[DeviceConfig]:
        order = self.kb.policies.deployment.get("stage_order", ["switch", "router"])
        rank = lambda d: (order.index(self.kb.devices[d.device].role)  # noqa: E731
                          if self.kb.devices[d.device].role in order else len(order), d.device)
        return sorted([d for d in devices if d.commands], key=rank)

    # ---------------------------------------------------------------- deployment
    def deploy(self, plan_id: str, *, dry_run: bool = True, record_state: bool = False) -> DeploymentReport:
        plan = self.load_plan(plan_id)
        if not plan.ok:
            raise PlanError(f"{plan_id} did not pass validation; refusing to deploy")
        if plan.state_fingerprint != self.store.fingerprint():
            raise PlanError("the network state changed since this plan was made; analyze the intent again")
        policy = self.kb.policies.deployment
        report = self._deployer().deploy(plan_id, self.ordered(plan.design.devices), [Probe(**p) for p in plan.probes],
                                         dry_run=dry_run, auto_rollback=policy.get("auto_rollback", True),
                                         save=policy.get("save_config", False))
        if report.success and (not dry_run or record_state):
            self._commit_state(plan)
        (self.package_dir(plan_id) / f"{report.deployment_id}.json").write_text(report.model_dump_json(indent=2))
        return report

    def _commit_state(self, plan: Plan) -> None:
        records, configs = self.store.records(), self.configs()
        (self.package_dir(plan.plan_id) / "state_before.json").write_text(json.dumps({
            "records": [r.model_dump(mode="json") for r in records], "configs": configs}, indent=2))
        now = datetime.now(timezone.utc)
        if plan.kind == "submit":
            records += [IntentRecord(intent=i, approach=plan.design.approach, devices=plan.design.devices,
                                     plan_id=plan.plan_id, updated_at=now) for i in plan.intents]
        else:
            withdrawn = {i.id for i in plan.intents}
            for r in records:
                if r.intent.id in withdrawn:
                    r.status, r.updated_at = IntentStatus.WITHDRAWN, now
        self.store.save(records, {**configs, **plan.configs_after})
        (self.package_dir(plan.plan_id) / "state_after.fingerprint").write_text(self.store.fingerprint())

    def rollback(self, plan_id: str, *, dry_run: bool = True, record_state: bool = False) -> DeploymentReport:
        """Undo the most recently committed plan with its rollback commands and restore IBN's state."""
        plan = self.load_plan(plan_id)
        d = self.package_dir(plan_id)
        fp, before = d / "state_after.fingerprint", d / "state_before.json"
        if not fp.is_file() or not before.is_file():
            raise PlanError(f"{plan_id} was never committed")
        if fp.read_text() != self.store.fingerprint():
            raise PlanError("other changes were committed after this plan; withdraw intents instead")
        reverse = [DeviceConfig(device=c.device, commands=c.rollback, rollback=c.commands)
                   for c in reversed(self.ordered(plan.design.devices))]
        report = self._deployer().deploy(f"{plan_id}-rollback", reverse, [], dry_run=dry_run, auto_rollback=True,
                                         save=self.kb.policies.deployment.get("save_config", False))
        if report.success and (not dry_run or record_state):
            state = json.loads(before.read_text())
            self.store.save([IntentRecord.model_validate(r) for r in state["records"]], state["configs"])
            fp.unlink()
        return report

    def sync_device(self, device: str, running_config: str) -> None:
        """A device's real running config replaces IBN's view of it."""
        (self.kb.path / "configs").mkdir(exist_ok=True)
        (self.kb.path / "configs" / f"{device}.cfg").write_text(running_config)
        self.store.save(configs={**self.store.stored_configs(), device: running_config})

    def _deployer(self) -> Deployer:
        return Deployer(self.kb, self.settings.backups_dir, self.audit)
