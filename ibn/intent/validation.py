"""Intent Layer validation of the AI's structured intent, before any configuration is designed:
syntax (schema), semantics (entities exist, no contradictions, guardrails) and conflicts with
intents that are already deployed."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ibn.intent.space import FlowSpace, space
from ibn.kb.knowledge_base import KBError, KnowledgeBase
from ibn.kb.state import IntentRecord
from ibn.models.intent import Intent
from ibn.models.report import StageResult, ValidationReport, error, info, warning


def parse_intents(raw: list[dict[str, Any]]) -> tuple[list[Intent], StageResult]:
    """Syntax validation: schema, required fields and data types."""
    stage = StageResult(name="Intent syntax (schema)")
    intents = []
    for idx, item in enumerate(raw, 1):
        try:
            intents.append(Intent.model_validate(item))
        except ValidationError as exc:
            for e in exc.errors():
                loc = ".".join(str(p) for p in e["loc"])
                stage.issues.append(error(f"intent #{idx} {loc}: {e['msg']}"))
    if not raw:
        stage.issues.append(error("no intent found in the request"))
    return intents, stage


def semantic_check(intents: list[Intent], kb: KnowledgeBase) -> StageResult:
    stage = StageResult(name="Intent semantics")
    for it in intents:
        sc = it.scope
        for name in sc.groups:
            if not kb.find_group(name):
                stage.issues.append(error(f"{it.id}: unknown group {name!r} (known: {', '.join(kb.groups)})"))
        for name in sc.hosts:
            if not kb.find_host(name):
                stage.issues.append(error(f"{it.id}: unknown host {name!r} (known: {', '.join(kb.hosts)})"))
        for name in sc.devices:
            if not any(d.lower() == name.lower() for d in kb.devices):
                stage.issues.append(error(f"{it.id}: unknown device {name!r} (known: {', '.join(kb.devices)})"))
        if not it.expectations:
            stage.issues.append(warning(f"{it.id}: no testable expectations; compliance will rely on the AI "
                                        "review and post-deployment checks"))
        protected = kb.policies.protected_subnets
        for exp in it.expectations:
            try:
                sp = space(exp, it, kb)
            except KBError as exc:
                stage.issues.append(error(f"{it.id}: expectation '{exp.label}': {exc}"))
                continue
            if sp.src.overlaps(sp.dst):
                stage.issues.append(error(f"{it.id}: expectation '{exp.label}': source and destination overlap"))
            if not sp.allow and any(sp.src.overlaps(n) for n in protected) and any(sp.dst.overlaps(n) for n in protected):
                stage.issues.append(error(f"{it.id}: guardrail: blocking traffic between protected infrastructure "
                                          f"subnets is not allowed ('{exp.label}')"))
    return stage


def detect_conflicts(new: list[Intent], existing: list[IntentRecord], kb: KnowledgeBase,
                     allow_override: bool = False) -> StageResult:
    """Opposite expectations on overlapping traffic must be decided by priority or specificity.
    Overriding an already deployed intent always needs the operator's explicit confirmation."""
    stage = StageResult(name="Conflict detection")
    old = [(sp, f"deployed {r.intent.id}") for r in existing for sp in _spaces(r.intent, kb)]
    fresh = [(sp, "same request") for it in new for sp in _spaces(it, kb)]
    for idx, (a, _) in enumerate(fresh):
        for b, where in old + fresh[idx + 1:]:
            if a.intent_id == b.intent_id or a.allow == b.allow or not a.overlaps(b):
                continue
            tag = f"'{a.label}' ({a.intent_id}) vs '{b.label}' ({where})"
            if where.startswith("deployed"):
                if allow_override and a.priority > b.priority:
                    stage.issues.append(warning(f"{tag}: overrides the deployed intent (confirmed by the operator)"))
                else:
                    stage.issues.append(error(f"{tag}: would override deployed intent {b.intent_id}; "
                                              "confirm the override or rephrase the request"))
            elif a.priority != b.priority:
                winner = a if a.priority > b.priority else b
                stage.issues.append(warning(f"{tag}: opposite expectations overlap; {winner.intent_id} wins by priority"))
            elif a.specificity != b.specificity and (a.contains(b) or b.contains(a)):
                stage.issues.append(info(f"{tag}: the more specific expectation takes precedence"))
            else:
                stage.issues.append(error(f"{tag}: contradictory expectations with equal priority - "
                                          "raise the priority of the one that should win"))
    return stage


def _spaces(intent: Intent, kb: KnowledgeBase) -> list[FlowSpace]:
    out = []
    for exp in intent.expectations:
        try:
            out.append(space(exp, intent, kb))
        except KBError:
            pass  # reported by semantic_check
    return out


def validate_intents(raw: list[dict[str, Any]], kb: KnowledgeBase, existing: list[IntentRecord],
                     allow_override: bool = False) -> tuple[list[Intent], ValidationReport]:
    report = ValidationReport(title="Intent validation")
    intents, syntax = parse_intents(raw)
    report.add(syntax)
    if not syntax.passed:
        return intents, report
    report.add(semantic_check(intents, kb))
    if report.passed:
        report.add(detect_conflicts(intents, existing, kb, allow_override))
    return intents, report
