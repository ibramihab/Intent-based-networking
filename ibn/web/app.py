"""Interface Layer: web GUI (FastAPI JSON API + a static single-page frontend)."""

from __future__ import annotations

import os
import threading
import webbrowser
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ibn.config import Settings, load_settings
from ibn.control.connection import ConnectionError_, connect
from ibn.intent.agent import IntentAgent
from ibn.intent.llm import GeminiProvider, LLMError, LLMProvider
from ibn.intent.validation import parse_intents
from ibn.kb.knowledge_base import KBError
from ibn.models.dataplane import Flow
from ibn.pipeline import IBN, Plan, PlanError
from ibn.validation.simulator import Simulator, build_models

STATIC = Path(__file__).parent / "static"
MAX_CONVERSATIONS = 50


class InterpretIn(BaseModel):
    text: str
    conversation_id: str | None = None  # set when answering clarification questions


class PlanIn(BaseModel):
    intents: list[dict[str, Any]]
    request: str
    conversation_id: str | None = None
    override: bool = False  # operator confirmed that the new intent overrides deployed ones


class DeployIn(BaseModel):
    live: bool = False
    record_state: bool = False


class SimulateIn(BaseModel):
    src: str
    dst: str
    protocol: Literal["icmp", "tcp", "udp"] = "icmp"
    port: int | None = None


def _gemini(settings: Settings) -> LLMProvider:
    return GeminiProvider(settings.gemini_api_key, settings.gemini_model)


def _plan_json(plan: Plan) -> dict[str, Any]:
    return plan.model_dump(mode="json", exclude={"configs_after"})


def create_app(settings_factory: Callable[[], Settings] = load_settings,
               provider_factory: Callable[[Settings], LLMProvider] | None = None) -> FastAPI:
    app = FastAPI(title="Intent-Based Networking")
    conversations: OrderedDict[str, IntentAgent] = OrderedDict()

    def core() -> IBN:
        try:
            return IBN(settings_factory())  # fresh per request so KB edits are picked up
        except KBError as exc:
            raise HTTPException(500, f"knowledge base error: {exc}") from exc

    def new_agent(ibn: IBN) -> IntentAgent | None:
        if not ibn.settings.gemini_api_key and provider_factory is None:
            return None
        return IntentAgent((provider_factory or _gemini)(ibn.settings), ibn.kb)

    def remember(cid: str, agent: IntentAgent) -> str:
        conversations[cid] = agent
        conversations.move_to_end(cid)
        while len(conversations) > MAX_CONVERSATIONS:
            conversations.popitem(last=False)
        return cid

    # ---------------------------------------------------------------- intent layer
    @app.post("/api/interpret")
    def interpret(body: InterpretIn) -> dict[str, Any]:
        ibn = core()
        active = ibn.store.active()
        try:
            if body.conversation_id:
                agent = conversations.get(body.conversation_id)
                if agent is None:
                    raise HTTPException(404, "conversation expired, please start again")
                result = agent.answer(body.text, active)
            else:
                agent = new_agent(ibn)
                if agent is None:
                    raise HTTPException(400, "The AI is not configured: put GEMINI_API_KEY in the .env file "
                                             "and restart IBN.")
                result = agent.parse(body.text, active)
            syntax = parse_intents(result.intents)[1] if result.intents else None
            if syntax and not syntax.passed:  # one self-repair round with the schema errors
                result = agent.repair_intents([i.message for i in syntax.issues], active)
        except LLMError as exc:
            raise HTTPException(502, str(exc)) from exc
        cid = remember(body.conversation_id or uuid4().hex, agent)
        return {"conversation_id": cid, "intents": result.intents, "clarifications": result.clarifications}

    # ---------------------------------------------------------------- plans
    @app.post("/api/plans")
    def create_plan(body: PlanIn) -> dict[str, Any]:
        ibn = core()
        raw = body.intents
        if body.override:
            top = max((r.intent.priority for r in ibn.store.active()), default=100)
            raw = [{**r, "priority": min(1000, top + 10)} for r in raw]
        agent = conversations.get(body.conversation_id or "") or new_agent(ibn)
        return _plan_json(ibn.plan_submit(raw, body.request, agent, allow_override=body.override))

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
        ibn = core()
        try:
            return _plan_json(ibn.plan_withdraw(intent_id, new_agent(ibn)))
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
            "gemini": bool(ibn.settings.gemini_api_key) or provider_factory is not None,
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
            "configs": ibn.configs(),
            "protected": [str(n) for n in k.policies.protected_subnets],
            "issues": [i.model_dump(mode="json") for i in k.check()],
        }

    @app.post("/api/simulate")
    def simulate(body: SimulateIn) -> dict[str, Any]:
        ibn = core()
        try:
            src = ibn.kb.representative_ip(ibn.kb.endpoint_net(body.src))
            dst = ibn.kb.representative_ip(ibn.kb.endpoint_net(body.dst))
        except KBError as exc:
            raise HTTPException(400, str(exc)) from exc
        flow = Flow(src, dst, body.protocol, body.port if body.protocol != "icmp" else None)
        verdict = Simulator(ibn.kb, build_models(ibn.kb, ibn.configs())).evaluate(flow)
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
            ibn.sync_device(name, text)
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
