"""Intent Layer validation: syntax (schema), semantics (entities exist, no contradictions)
and conflict detection against intents that are already deployed."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ibn.intent.space import spaces, specificity
from ibn.kb.knowledge_base import KBError, KnowledgeBase
from ibn.kb.state import IntentRecord
from ibn.models.intent import Action, Intent
from ibn.models.report import Issue, StageResult, ValidationReport, error, info, warning


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


def semantic_check(intents: list[Intent], kb: KnowledgeBase) -> tuple[list[Intent], StageResult]:
    """Entities exist (names are canonicalised), and the intent is not self-contradictory."""
    stage = StageResult(name="Intent semantics")
    out = []
    for it in intents:
        try:
            it = it.model_copy(update={"source": kb.canonical(it.source), "destination": kb.canonical(it.destination)})
            src, dst = kb.resolve(it.source), kb.resolve(it.destination)
        except KBError as exc:
            stage.issues.append(error(f"{it.id}: {exc}"))
            continue
        protected = kb.policies.protected_subnets
        if it.action == Action.DENY and any(src.overlaps(n) for n in protected) \
                and any(dst.overlaps(n) for n in protected):
            stage.issues.append(error(f"{it.id}: guardrail: denying traffic between protected infrastructure "
                                      f"subnets ({src} -> {dst}) is not allowed"))
        if src.overlaps(dst):
            stage.issues.append(error(f"{it.id}: source {src} and destination {dst} overlap"))
        for ep, net in ((it.source, src), (it.destination, dst)):
            if ep.subnet and not kb.locate(net) and not any(net.subnet_of(g.subnet) for g in kb.groups.values()):
                stage.issues.append(warning(f"{it.id}: subnet {net} is not attached to any known router interface"))
        labels = [s.label for s in it.services]
        if len(set(labels)) != len(labels):
            stage.issues.append(warning(f"{it.id}: duplicate services {labels}"))
        out.append(it)
    return out, stage


def detect_conflicts(new: list[Intent], existing: list[IntentRecord], kb: KnowledgeBase) -> StageResult:
    """Overlapping traffic with opposite actions must be resolvable by priority or specificity."""
    stage = StageResult(name="Conflict detection")
    others = [(r.intent, "deployed") for r in existing]
    for idx, a in enumerate(new):
        candidates = others + [(b, "same request") for b in new[idx + 1:]]
        for b, where in candidates:
            stage.issues += _compare(a, b, where, kb)
    return stage


def _compare(a: Intent, b: Intent, where: str, kb: KnowledgeBase) -> list[Issue]:
    sa, sb = spaces(a, kb), spaces(b, kb)
    if not any(x.overlaps(y) for x in sa for y in sb):
        return []
    tag = f"{a.id} vs {b.id} ({where}: {b.summary()})"
    if a.action == b.action:
        if all(any(y.contains(x) for y in sb) for x in sa):
            return [warning(f"{tag}: redundant, already covered")]
        return [info(f"{tag}: overlapping, same action")]
    if a.priority != b.priority:
        winner = a if a.priority > b.priority else b
        return [warning(f"{tag}: opposite actions overlap; {winner.id} wins by priority")]
    order = {(specificity(x) > specificity(y)) - (specificity(x) < specificity(y))
             for x in sa for y in sb if x.overlaps(y)}
    if order in ({1}, {-1}):
        winner = a if order == {1} else b
        return [warning(f"{tag}: opposite actions overlap; more specific {winner.id} takes precedence")]
    return [error(f"{tag}: opposite actions on partially overlapping traffic with equal priority - "
                  "set a priority or narrow one intent")]


def validate_intents(raw: list[dict[str, Any]], kb: KnowledgeBase,
                     existing: list[IntentRecord]) -> tuple[list[Intent], ValidationReport]:
    report = ValidationReport(title="Intent validation")
    intents, syntax = parse_intents(raw)
    report.add(syntax)
    if not syntax.passed:
        return intents, report
    intents, semantic = semantic_check(intents, kb)
    report.add(semantic)
    if semantic.passed:
        report.add(detect_conflicts(intents, existing, kb))
    return intents, report
