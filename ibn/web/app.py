"""Interface Layer: web GUI (FastAPI JSON API + a static single-page frontend)."""

from __future__ import annotations

import ipaddress
import os
import threading
import webbrowser
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ibn.config import Settings, load_settings
from ibn.control.connection import ConnectionError_, connect
from ibn.intent.llm import GeminiProvider, LLMError
from ibn.intent.parser import LLMIntentParser, RuleBasedParser
from ibn.intent.validation import parse_intents
from ibn.kb.knowledge_base import KBError
from ibn.models.intent import Endpoint, Protocol, SolutionKind
from ibn.pipeline import IBN, Plan, PlanError
from ibn.validation.simulator import Flow, Simulator

STATIC = Path(__file__).parent / "static"


class InterpretIn(BaseModel):
    text: str
    offline: bool = False
    conversation_id: str | None = None  # set when answering clarification questions


class PlanIn(BaseModel):
    intents: list[dict[str, Any]]
    request: str
    solution: SolutionKind | None = None
    raise_priority: bool = False


class DeployIn(BaseModel):
    live: bool = False
    record_state: bool = False


class SimulateIn(BaseModel):
    src: str
    dst: str
    protocol: Protocol = Protocol.ICMP
    port: int | None = None


def _plan_json(plan: Plan) -> dict[str, Any]:
    return plan.model_dump(mode="json")


def create_app(settings_factory: Callable[[], Settings] = load_settings) -> FastAPI:
    app = FastAPI(title="Intent-Based Networking")
    conversations: dict[str, LLMIntentParser] = {}

    def core() -> IBN:
        try:
            return IBN(settings_factory())  # fresh per request so KB edits are picked up
        except KBError as exc:
            raise HTTPException(500, f"knowledge base error: {exc}") from exc

    # ---------------------------------------------------------------- intent layer
    @app.post("/api/interpret")
    def interpret(body: InterpretIn) -> dict[str, Any]:
        ibn = core()
        parser: LLMIntentParser | None = None
        try:
            if body.conversation_id:
                parser = conversations.pop(body.conversation_id, None)
                if parser is None:
                    raise HTTPException(404, "conversation expired, please start again")
                result = parser.answer(body.text)
            elif body.offline or not ibn.settings.gemini_api_key:
                result = RuleBasedParser(ibn.kb).parse(body.text)
            else:
                parser = LLMIntentParser(GeminiProvider(ibn.settings.gemini_api_key, ibn.settings.gemini_model), ibn.kb)
                result = parser.parse(body.text)
            syntax = parse_intents(result.intents)[1] if parser and result.intents else None
            if syntax and not syntax.passed:  # one self-repair round with the schema errors
                result = parser.parse("Your JSON failed schema validation: "
                                      + "; ".join(i.message for i in syntax.issues) + ". Return corrected JSON.")
        except LLMError as exc:
            raise HTTPException(502, str(exc)) from exc
        cid = None
        if parser and result.clarifications:
            cid = uuid4().hex
            conversations[cid] = parser
        return {"conversation_id": cid, "intents": result.intents, "clarifications": result.clarifications,
                "parser": "gemini" if parser else "offline"}

    # ---------------------------------------------------------------- plans
    @app.post("/api/plans")
    def create_plan(body: PlanIn) -> dict[str, Any]:
        ibn = core()
        raw = body.intents
        if body.raise_priority:
            top = max((r.intent.priority for r in ibn.store.active()), default=100)
            raw = [{**r, "priority": min(1000, top + 10)} for r in raw]
        return _plan_json(ibn.plan_submit(raw, body.request, body.solution))

    @app.get("/api/plans/{plan_id}")
    def get_plan(plan_id: str) -> dict[str, Any]:
        try:
            return _plan_json(core().load_plan(plan_id))
        except PlanError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/plans/{plan_id}/deploy")
    def deploy(plan_id: str, body: DeployIn) -> dict[str, Any]:
        try:
            rep = core().deploy(plan_id, dry_run=not body.live, record_state=body.record_state)
        except PlanError as exc:
            raise HTTPException(400, str(exc)) from exc
        return rep.model_dump(mode="json")

    @app.post("/api/plans/{plan_id}/rollback")
    def rollback(plan_id: str, body: DeployIn) -> dict[str, Any]:
        try:
            rep = core().rollback(plan_id, dry_run=not body.live, record_state=body.record_state)
        except PlanError as exc:
            raise HTTPException(400, str(exc)) from exc
        return rep.model_dump(mode="json")

    # ---------------------------------------------------------------- dashboard
    @app.get("/api/intents")
    def intents() -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") | {"summary": r.intent.summary()} for r in core().store.records()]

    @app.post("/api/intents/{intent_id}/withdraw")
    def withdraw(intent_id: str) -> dict[str, Any]:
        try:
            return _plan_json(core().plan_withdraw(intent_id))
        except PlanError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/history")
    def history(limit: int = 100) -> list[dict[str, Any]]:
        return list(reversed(core().audit.read(limit)))

    # ---------------------------------------------------------------- knowledge base
    @app.get("/api/kb")
    def kb() -> dict[str, Any]:
        ibn = core()
        k = ibn.kb
        return {
            "gemini": bool(ibn.settings.gemini_api_key),
            "model": ibn.settings.gemini_model,
            "groups": [{"name": g.name, "subnet": str(g.subnet), "gateway": f"{g.gateway_device} {g.gateway_interface}",
                        "switch": g.switch} for g in k.groups.values()],
            "hosts": [{"name": h.name, "ip": str(h.ip), "group": h.group, "attach": f"{h.switch} {h.port}"}
                      for h in k.hosts.values()],
            "devices": [{"name": d.name, "role": d.role, "platform": d.platform, "os": d.os_version,
                         "mgmt": f"{d.mgmt.transport}://{d.mgmt.host}:{d.mgmt.port}",
                         "capabilities": sorted(d.capabilities),
                         "interfaces": [{"name": i.name, "ip": str(i.ip) if i.ip else "",
                                         "vlan": i.vlan, "description": i.description}
                                        for i in k.interfaces.get(d.name, {}).values()]}
                        for d in k.devices.values()],
            "protected": [str(n) for n in k.policies.protected_subnets],
            "issues": [i.model_dump(mode="json") for i in k.check()],
        }

    @app.post("/api/simulate")
    def simulate(body: SimulateIn) -> dict[str, Any]:
        ibn = core()

        def addr(x: str) -> str:
            try:
                return str(ipaddress.IPv4Address(x.strip()))
            except ValueError:
                ep = Endpoint(host=x) if ibn.kb.find_host(x) else Endpoint(group=x)
                return ibn.kb.representative_ip(ibn.kb.resolve(ep))

        try:
            flow = Flow(addr(body.src), addr(body.dst), body.protocol, body.port)
        except KBError as exc:
            raise HTTPException(400, str(exc)) from exc
        verdict = Simulator(ibn.kb, ibn.store.managed()).evaluate(flow)
        return {"flow": str(flow), "allowed": verdict.allowed, "trace": verdict.trace}

    @app.post("/api/kb/sync")
    def kb_sync() -> list[dict[str, Any]]:
        ibn = core()
        results = []
        for name in ibn.kb.devices:
            try:
                conn = connect(ibn.kb, name, dry_run=False)
                conn.open()
                text = conn.send_command("show running-config")
                conn.close()
            except ConnectionError_ as exc:
                results.append({"device": name, "ok": False, "message": str(exc)})
                continue
            (ibn.kb.path / "configs" / f"{name}.cfg").write_text(text)
            results.append({"device": name, "ok": True, "message": f"saved {len(text.splitlines())} lines"})
        return results

    # ---------------------------------------------------------------- frontend
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    return app


def main() -> None:
    import uvicorn

    host = os.environ.get("IBN_HOST", "127.0.0.1")
    port = int(os.environ.get("IBN_PORT", "8000"))
    url = f"http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}"
    print(f"IBN web interface: {url}  (press Ctrl+C to stop)")
    if os.environ.get("IBN_NO_BROWSER") != "1":
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    uvicorn.run(create_app(), host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
