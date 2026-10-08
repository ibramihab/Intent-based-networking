"""Command-line interface (stand-in for the Web UI layer)."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ibn.config import load_settings
from ibn.control.connection import ConnectionError_, connect
from ibn.control.deployer import DeploymentReport
from ibn.intent.llm import GeminiProvider, LLMError
from ibn.intent.parser import LLMIntentParser, RuleBasedParser
from ibn.intent.validation import parse_intents
from ibn.models.intent import Endpoint, Protocol, SolutionKind
from ibn.models.report import Severity, ValidationReport
from ibn.pipeline import IBN, Plan, PlanError
from ibn.validation.simulator import Flow, Simulator

app = typer.Typer(help="Intent-Based Networking CLI", no_args_is_help=True, pretty_exceptions_show_locals=False)
kb_app = typer.Typer(help="Network Knowledge Base", no_args_is_help=True)
app.add_typer(kb_app, name="kb")
console = Console()

COLORS = {Severity.ERROR: "red", Severity.WARNING: "yellow", Severity.INFO: "dim"}

Offline = typer.Option(False, "--offline", help="use the rule-based parser instead of Gemini")
Live = typer.Option(False, "--live", help="push to real devices (default: dry-run)")
Yes = typer.Option(False, "--yes", "-y", help="skip the approval prompt")
Record = typer.Option(False, "--record-state", help="in dry-run, still record the result as deployed")


def _ibn() -> IBN:
    return IBN(load_settings())


# ------------------------------------------------------------------ rendering
def show_report(report: ValidationReport, verbose: bool = False) -> None:
    for stage in report.stages:
        status = "[dim]skipped[/]" if stage.skipped else ("[green]pass[/]" if stage.passed else "[red]FAIL[/]")
        console.print(f"  {status}  {stage.name}")
        for issue in stage.issues:
            if issue.severity != Severity.INFO or verbose or stage.skipped:
                console.print(f"        [{COLORS[issue.severity]}]{issue}[/]", highlight=False)


def show_plan(plan: Plan, verbose: bool = False) -> None:
    t = Table(title="Structured intent", show_lines=False)
    for col in ("id", "action", "source", "destination", "services", "dir", "prio"):
        t.add_column(col)
    for it in plan.intents:
        t.add_row(it.id, it.action.value, it.source.label, it.destination.label,
                  " ".join(s.label for s in it.services), "both" if it.bidirectional else "one-way", str(it.priority))
    console.print(t)
    if plan.intent_report:
        console.print("[bold]Intent layer validation[/]")
        show_report(plan.intent_report, verbose)
    if plan.options:
        t = Table(title="Solution selector")
        for col in ("solution", "feasible", "score", "why"):
            t.add_column(col)
        for o in plan.options:
            mark = " ✔ chosen" if plan.chosen and o["kind"] == plan.chosen.value else ""
            t.add_row(o["kind"] + mark, "yes" if o["feasible"] else "no", str(o["score"]), "\n".join(o["reasons"]))
        console.print(t)
    for a in plan.attempts:
        if not a.passed:
            console.print(f"[yellow]Attempt with {a.solution.value} failed validation → trying next option[/]")
    if plan.candidate:
        if not plan.candidate.changes:
            console.print("[green]No configuration change is needed.[/]")
        for ch in plan.candidate.changes:
            console.print(Panel("\n".join(ch.commands), title=f"{ch.device} ({ch.platform}) – candidate config",
                                border_style="cyan"))
            if verbose:
                console.print(Panel("\n".join(ch.rollback), title=f"{ch.device} – rollback", border_style="dim"))
    if plan.validation:
        console.print(f"[bold]Validation[/] ({plan.chosen.value})")
        show_report(plan.validation, verbose)
    if plan.probes:
        console.print("[bold]Post-deployment probes[/]")
        for p in plan.probes:
            console.print(f"  • {p['device']}: ping {p['target']} source {p['source_interface']} → expect "
                          f"{'success' if p['expected'] else 'failure'} ({p['purpose']})")
    color = "green" if plan.ok else "red"
    console.print(f"[{color}]Plan {plan.plan_id}: {'READY' if plan.ok else 'NOT DEPLOYABLE'}[/]  "
                  f"(package: artifacts/{plan.plan_id}/)")


def show_deployment(rep: DeploymentReport) -> None:
    t = Table(title=f"Deployment {rep.deployment_id} ({'dry-run' if rep.dry_run else 'LIVE'})")
    for col in ("device", "status", "backup", "details"):
        t.add_column(col)
    for d in rep.devices:
        t.add_row(d.device, d.status, d.backup or "", "\n".join(d.errors or d.verification))
    console.print(t)
    for p in rep.probes:
        res = "not run" if p.actual is None else ("ok" if p.ok else "MISMATCH")
        console.print(f"  probe: {p.probe} → {res}")
    for m in rep.messages:
        console.print(f"  {m}")
    console.print("[green]SUCCESS[/]" if rep.success else "[red]FAILED[/]")


# ------------------------------------------------------------------ parsing
def interpret(ibn: IBN, text: str, offline: bool) -> list[dict[str, Any]]:
    settings = ibn.settings
    if offline or not settings.gemini_api_key:
        if not offline:
            console.print("[yellow]GEMINI_API_KEY not set – using the offline rule-based parser[/]")
        result = RuleBasedParser(ibn.kb).parse(text)
        if result.clarifications:
            raise typer.BadParameter(" ".join(result.clarifications))
        return result.intents

    parser = LLMIntentParser(GeminiProvider(settings.gemini_api_key, settings.gemini_model), ibn.kb)
    with console.status(f"Asking {settings.gemini_model}…"):
        result = parser.parse(text)
    for _ in range(3):  # ambiguity resolution: ask the operator
        if not result.clarifications:
            break
        console.print("[bold yellow]The intent is ambiguous:[/]")
        for q in result.clarifications:
            console.print(f"  ? {q}")
        result = parser.answer(typer.prompt("Your answer"))
    if result.clarifications:
        raise typer.BadParameter("intent is still ambiguous: " + " ".join(result.clarifications))
    _, syntax = parse_intents(result.intents)
    if not syntax.passed:  # one self-repair round with the schema errors
        result = parser.parse("Your JSON failed schema validation: "
                              + "; ".join(i.message for i in syntax.issues) + ". Return corrected JSON.")
    return result.intents


def _raise_priority(ibn: IBN, raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    top = max((r.intent.priority for r in ibn.store.active()), default=100)
    return [{**r, "priority": min(1000, top + 10)} for r in raw]


def _plan_request(ibn: IBN, text: str, offline: bool, solution: Optional[SolutionKind],
                  verbose: bool, yes: bool) -> Plan:
    try:
        raw = interpret(ibn, text, offline)
    except LLMError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    plan = ibn.plan_submit(raw, text, solution)
    conflict = next((s for s in (plan.intent_report.stages if plan.intent_report else [])
                     if s.name == "Conflict detection" and not s.passed), None)
    if conflict:
        show_plan(plan, verbose)
        if not yes and typer.confirm("Conflicts with deployed intents. Give the new intent higher priority?"):
            plan = ibn.plan_submit(_raise_priority(ibn, raw), text, solution)
        else:
            raise typer.Exit(1)
    show_plan(plan, verbose)
    return plan


def _deploy(ibn: IBN, plan_id: str, live: bool, yes: bool, record: bool) -> None:
    mode = "LIVE devices" if live else "dry-run"
    if not yes and not typer.confirm(f"Approve deployment of {plan_id} to {mode}?"):
        console.print("Not deployed. You can deploy later with: ibn deploy " + plan_id)
        raise typer.Exit(0)
    try:
        rep = ibn.deploy(plan_id, dry_run=not live, record_state=record)
    except PlanError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    show_deployment(rep)
    if not rep.success:
        raise typer.Exit(1)


# ------------------------------------------------------------------ commands
@app.command()
def submit(text: str = typer.Argument(..., help="intent in natural language"), offline: bool = Offline,
           solution: Optional[SolutionKind] = typer.Option(None, help="force a solution"),
           live: bool = Live, yes: bool = Yes, record_state: bool = Record,
           verbose: bool = typer.Option(False, "-v", "--verbose")):
    """Parse, validate, translate, validate config, ask for approval, deploy."""
    ibn = _ibn()
    plan = _plan_request(ibn, text, offline, solution, verbose, yes)
    if not plan.ok:
        raise typer.Exit(1)
    _deploy(ibn, plan.plan_id, live, yes, record_state)


@app.command()
def plan(text: str = typer.Argument(...), offline: bool = Offline,
         solution: Optional[SolutionKind] = typer.Option(None), verbose: bool = typer.Option(False, "-v", "--verbose")):
    """Everything up to the validated config package; nothing is deployed."""
    p = _plan_request(_ibn(), text, offline, solution, verbose, yes=False)
    raise typer.Exit(0 if p.ok else 1)


@app.command()
def deploy(plan_id: str, live: bool = Live, yes: bool = Yes, record_state: bool = Record):
    """Deploy a previously validated plan."""
    _deploy(_ibn(), plan_id, live, yes, record_state)


@app.command()
def withdraw(intent_id: str, live: bool = Live, yes: bool = Yes, record_state: bool = Record,
             verbose: bool = typer.Option(False, "-v", "--verbose")):
    """Remove a deployed intent (config is regenerated without it)."""
    ibn = _ibn()
    try:
        p = ibn.plan_withdraw(intent_id)
    except PlanError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    show_plan(p, verbose)
    if not p.ok:
        raise typer.Exit(1)
    _deploy(ibn, p.plan_id, live, yes, record_state)


@app.command()
def rollback(plan_id: str, live: bool = Live, yes: bool = Yes, record_state: bool = Record):
    """Undo the most recently committed plan with its stored rollback commands."""
    if not yes and not typer.confirm(f"Roll back {plan_id} on {'LIVE devices' if live else 'dry-run'}?"):
        raise typer.Exit(0)
    try:
        rep = _ibn().rollback(plan_id, dry_run=not live, record_state=record_state)
    except PlanError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)
    show_deployment(rep)


@app.command()
def intents():
    """Intent history and status."""
    t = Table(title="Intents")
    for col in ("id", "status", "solution", "intent", "plan", "updated"):
        t.add_column(col)
    for r in _ibn().store.records():
        t.add_row(r.intent.id, r.status.value, r.solution.value, r.intent.summary(), r.plan_id or "",
                  f"{r.updated_at:%Y-%m-%d %H:%M}" if r.updated_at else "")
    console.print(t)


@app.command()
def history(limit: int = 20):
    """Audit log."""
    for e in _ibn().audit.read(limit):
        extra = {k: v for k, v in e.items() if k not in ("ts", "user", "event", "commands")}
        console.print(f"{e['ts'][:19]} {e['user']:<8} {e['event']:<16} {extra}", highlight=False)


@app.command()
def simulate(src: str, dst: str, protocol: Protocol = typer.Option(Protocol.ICMP, "--proto"),
             port: Optional[int] = typer.Option(None)):
    """Trace a flow through the current managed state. SRC/DST: host, group or IP."""
    ibn = _ibn()

    def addr(x: str) -> str:
        try:
            return str(ipaddress.IPv4Address(x))
        except ValueError:
            ep = Endpoint(host=x) if ibn.kb.find_host(x) else Endpoint(group=x)
            return ibn.kb.representative_ip(ibn.kb.resolve(ep))

    flow = Flow(addr(src), addr(dst), protocol, port)
    v = Simulator(ibn.kb, ibn.store.managed()).evaluate(flow)
    console.print(f"{flow}: {'[green]PERMIT[/]' if v.allowed else '[red]DENY[/]'}")
    for line in v.trace:
        console.print(f"  {line}", highlight=False)


@kb_app.command("check")
def kb_check():
    """Validate the knowledge base (IP overlaps, references, addressing convention)."""
    issues = _ibn().kb.check()
    for i in issues:
        console.print(f"[{COLORS[i.severity]}]{i}[/]")
    if not issues:
        console.print("[green]Knowledge base is consistent.[/]")
    raise typer.Exit(1 if any(i.severity == Severity.ERROR for i in issues) else 0)


@kb_app.command("show")
def kb_show():
    """Print the KB as the intent layer sees it."""
    console.print(_ibn().kb.llm_context(), highlight=False)


@kb_app.command("sync")
def kb_sync(device: Optional[list[str]] = typer.Option(None, "--device", "-d")):
    """Pull running configs from devices into kb/configs/ (used for collision checks and Batfish)."""
    ibn = _ibn()
    for name in device or list(ibn.kb.devices):
        try:
            conn = connect(ibn.kb, name, dry_run=False)
            conn.open()
            text = conn.send_command("show running-config")
            conn.close()
        except ConnectionError_ as exc:
            console.print(f"[red]{exc}[/]")
            continue
        (ibn.kb.path / "configs" / f"{name}.cfg").write_text(text)
        console.print(f"[green]{name}: saved {len(text.splitlines())} lines[/]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
