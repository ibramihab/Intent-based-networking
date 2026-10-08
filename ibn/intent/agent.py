"""The Intent Layer agent: understands requests, asks for clarification, and designs configuration.

Two conversations are kept: one for understanding (with the operator's answers) and one for design
(with the validator's rejections), so each step sees its own history.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ibn.intent import prompts
from ibn.intent.llm import LLMProvider
from ibn.kb.knowledge_base import KnowledgeBase
from ibn.kb.state import IntentRecord
from ibn.models.design import ConfigDesign
from ibn.models.intent import Intent


@dataclass
class ParseResult:
    intents: list[dict[str, Any]] = field(default_factory=list)
    clarifications: list[str] = field(default_factory=list)


def _deployed(records: list[IntentRecord], with_config: bool) -> str:
    if not records:
        return "  (none)"
    out = []
    for r in records:
        exps = "; ".join(e.label for e in r.intent.expectations) or "no expectations"
        out.append(f"  - {r.intent.id} prio {r.intent.priority}: {r.intent.description} [{exps}]"
                   + (f" via {r.approach}" if r.approach else ""))
        if with_config:
            for d in r.devices:
                out.append(f"      {d.device}: " + " | ".join(d.commands))
    return "\n".join(out)


def _configs(configs: dict[str, str], devices: list[str] | None = None) -> str:
    return "\n".join(f"--- {dev} ---\n{text.strip()}" for dev, text in configs.items()
                     if devices is None or dev in devices)


class IntentAgent:
    def __init__(self, provider: LLMProvider, kb: KnowledgeBase):
        self.provider = provider
        self.kb = kb
        self.understand_history: list[dict[str, str]] = []
        self.design_history: list[dict[str, str]] = []
        self._design_system = ""

    # ---------------------------------------------------------------- step 1: understand
    def parse(self, text: str, deployed: list[IntentRecord]) -> ParseResult:
        system = prompts.UNDERSTAND.format(kb=self.kb.llm_context(), deployed=_deployed(deployed, False))
        data = self._ask(system, self.understand_history, text)
        return ParseResult(intents=list(data.get("intents") or []),
                           clarifications=list(data.get("clarifications") or []))

    def answer(self, text: str, deployed: list[IntentRecord]) -> ParseResult:
        return self.parse(f"Answers to your questions: {text}", deployed)

    def repair_intents(self, errors: list[str], deployed: list[IntentRecord]) -> ParseResult:
        return self.parse("Your JSON failed validation: " + "; ".join(errors) + ". Return corrected JSON.", deployed)

    # ---------------------------------------------------------------- step 2: design
    def design(self, intents: list[Intent], configs: dict[str, str], deployed: list[IntentRecord]) -> dict[str, Any]:
        self.design_history = []
        self._design_system = self._design_prompt(configs, deployed)
        request = "Design the configuration for these validated intents:\n" + json.dumps(
            [i.model_dump(mode="json", exclude={"created_at"}) for i in intents], indent=1)
        return self._ask(self._design_system, self.design_history, request)

    def withdraw(self, record: IntentRecord, configs: dict[str, str], deployed: list[IntentRecord]) -> dict[str, Any]:
        self.design_history = []
        self._design_system = self._design_prompt(configs, deployed)
        owned = "\n".join(f"  {d.device}: commands {d.commands} / rollback {d.rollback}" for d in record.devices)
        request = prompts.WITHDRAW.format(intent_id=record.intent.id, description=record.intent.description,
                                          owned=owned or "  (nothing recorded)")
        return self._ask(self._design_system, self.design_history, request)

    def redesign(self, errors: list[str]) -> dict[str, Any]:
        msg = ("The Validation Layer rejected your design:\n- " + "\n- ".join(errors)
               + "\nFix every error and return the complete corrected JSON.")
        return self._ask(self._design_system, self.design_history, msg)

    def _design_prompt(self, configs: dict[str, str], deployed: list[IntentRecord]) -> str:
        platforms = ", ".join(f"{d.name}={d.platform}" for d in self.kb.devices.values())
        return prompts.DESIGN.format(kb=self.kb.llm_context(), platforms=platforms, configs=_configs(configs),
                                     deployed=_deployed(deployed, True), prefix=self.kb.policies.object_prefix)

    # ---------------------------------------------------------------- independent review
    def review(self, intents: list[Intent], design: ConfigDesign, configs: dict[str, str]) -> dict[str, Any]:
        devices = [d.device for d in design.devices]
        change = "\n".join(f"--- {d.device} commands ---\n" + "\n".join(d.commands)
                           + f"\n--- {d.device} rollback ---\n" + "\n".join(d.rollback) for d in design.devices)
        system = prompts.REVIEW.format(
            kb=self.kb.llm_context(), configs=_configs(configs, devices),
            intents=json.dumps([i.model_dump(mode="json", exclude={"created_at"}) for i in intents], indent=1),
            approach=design.approach, change=change)
        return self.provider.generate_json(system, [{"role": "user", "text": "Review this change."}])

    # ---------------------------------------------------------------- plumbing
    def _ask(self, system: str, history: list[dict[str, str]], text: str) -> dict[str, Any]:
        history.append({"role": "user", "text": text})
        data = self.provider.generate_json(system, history)
        history.append({"role": "model", "text": json.dumps(data)})
        return data if isinstance(data, dict) else {}
