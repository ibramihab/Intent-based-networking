"""Control Layer deployment: backup -> staged apply -> verify -> probes -> (rollback) -> report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from ibn.control.audit import AuditLog
from ibn.control.connection import ConnectionError_, DeviceConnection, connect
from ibn.control.verifier import Probe
from ibn.kb.knowledge_base import KnowledgeBase
from ibn.models.design import DeviceConfig
from ibn.platforms import get_platform


class DeviceResult(BaseModel):
    device: str
    status: Literal["pending", "applied", "failed", "rolled_back", "rollback_failed"] = "pending"
    backup: str | None = None
    errors: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)


class ProbeResult(BaseModel):
    probe: str
    expected: bool
    actual: bool | None  # None = not executed (dry-run)
    ok: bool


class DeploymentReport(BaseModel):
    deployment_id: str
    plan_id: str
    dry_run: bool
    started: datetime
    finished: datetime | None = None
    success: bool = False
    rolled_back: bool = False
    devices: list[DeviceResult] = Field(default_factory=list)
    probes: list[ProbeResult] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)


class _Abort(Exception):
    pass


class Deployer:
    def __init__(self, kb: KnowledgeBase, backups_dir: Path, audit: AuditLog,
                 connector: Callable[[KnowledgeBase, str, bool], DeviceConnection] = connect):
        self.kb = kb
        self.backups_dir = Path(backups_dir)
        self.audit = audit
        self.connector = connector

    def deploy(self, plan_id: str, changes: list[DeviceConfig], probes: list[Probe], *, dry_run: bool,
               auto_rollback: bool = True, save: bool = False) -> DeploymentReport:
        rep = DeploymentReport(deployment_id=f"dep-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{uuid4().hex[:4]}",
                               plan_id=plan_id, dry_run=dry_run, started=datetime.now(timezone.utc))
        self.audit.write("deploy.start", deployment=rep.deployment_id, plan=plan_id, dry_run=dry_run,
                         devices=[c.device for c in changes])
        conns: dict[str, DeviceConnection] = {}
        touched: list[tuple[DeviceConfig, DeviceResult]] = []
        try:
            for ch in changes:  # staged rollout: one device at a time
                res = DeviceResult(device=ch.device)
                rep.devices.append(res)
                touched.append((ch, res))
                self._apply(ch, res, rep, conns, dry_run)
            self._run_probes(probes, rep, conns, dry_run)
            if not all(p.ok for p in rep.probes):
                raise _Abort("post-deployment reachability verification failed")
            if save and not dry_run:
                for ch in changes:
                    conns[ch.device].save()
                rep.messages.append("configuration saved (write memory)")
            rep.success = True
        except (_Abort, ConnectionError_) as exc:
            rep.messages.append(f"deployment failed: {exc}")
            if auto_rollback:
                self._rollback(touched, conns, dry_run, rep)
            else:
                rep.messages.append("auto-rollback disabled: devices left as they are")
        finally:
            for c in conns.values():
                try:
                    c.close()
                except Exception:
                    pass
            rep.finished = datetime.now(timezone.utc)
            self.audit.write("deploy.end", deployment=rep.deployment_id, plan=plan_id, success=rep.success,
                             rolled_back=rep.rolled_back, dry_run=dry_run)
        return rep

    def _apply(self, ch: DeviceConfig, res: DeviceResult, rep: DeploymentReport,
               conns: dict[str, DeviceConnection], dry_run: bool) -> None:
        driver = get_platform(self.kb.devices[ch.device].platform)
        try:
            conn = self.connector(self.kb, ch.device, dry_run)
            conn.open()
        except ConnectionError_ as exc:
            res.status, res.errors = "failed", [str(exc)]
            raise
        conns[ch.device] = conn

        backup = self.backups_dir / rep.deployment_id / f"{ch.device}.cfg"
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_text(conn.send_command("show running-config"))
        res.backup = str(backup)

        output = conn.send_config(ch.commands)
        self.audit.write("device.config", deployment=rep.deployment_id, device=ch.device, commands=ch.commands)
        if errors := driver.command_errors(output):
            res.status, res.errors = "failed", errors
            raise _Abort(f"{ch.device} rejected commands: {errors[0]}")
        if dry_run:
            res.verification.append("dry-run: running-config checks not executed")
        else:
            problems = []
            for chk in ch.verify:
                if not driver.is_read_only(chk.command):  # validated already; never run anything else
                    problems.append(f"refused to run non read-only command '{chk.command}'")
                    continue
                problems += chk.evaluate(conn.send_command(chk.command))
            res.verification = problems or [f"{len(ch.verify)} verification command(s) passed"]
            if problems:
                res.status, res.errors = "failed", problems
                raise _Abort(f"{ch.device} running config does not match: {problems[0]}")
        res.status = "applied"

    def _run_probes(self, probes: list[Probe], rep: DeploymentReport,
                    conns: dict[str, DeviceConnection], dry_run: bool) -> None:
        for p in probes:
            if dry_run:
                rep.probes.append(ProbeResult(probe=str(p), expected=p.expected, actual=None, ok=True))
                continue
            conn = conns.get(p.device)
            if conn is None:
                conn = self.connector(self.kb, p.device, False)
                conn.open()
                conns[p.device] = conn
            driver = get_platform(self.kb.devices[p.device].platform)
            actual = driver.ping_succeeded(conn.send_command(driver.ping_command(p.target, p.source_interface)))
            rep.probes.append(ProbeResult(probe=str(p), expected=p.expected, actual=actual, ok=actual == p.expected))

    def _rollback(self, touched: list[tuple[DeviceConfig, DeviceResult]], conns: dict[str, DeviceConnection],
                  dry_run: bool, rep: DeploymentReport) -> None:
        rep.rolled_back = True
        for ch, res in reversed(touched):
            conn = conns.get(ch.device)
            if conn is None:
                continue
            driver = get_platform(self.kb.devices[ch.device].platform)
            errors = driver.command_errors(conn.send_config(ch.rollback))
            res.status = "rollback_failed" if errors else "rolled_back"
            res.errors += [f"rollback: {e}" for e in errors]
            self.audit.write("device.rollback", deployment=rep.deployment_id, device=ch.device,
                             commands=ch.rollback, ok=res.status == "rolled_back")
        rep.messages.append("rolled back all touched devices (reverse order)")
