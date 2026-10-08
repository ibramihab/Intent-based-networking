"""Natural language -> structured intent JSON.

`LLMIntentParser` grounds the LLM in the Knowledge Base and asks it to either return intents
or clarification questions. `RuleBasedParser` is an offline fallback for tests and demos.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ibn.intent.llm import LLMProvider
from ibn.kb.knowledge_base import KnowledgeBase

SYSTEM_PROMPT = """You are the intent parser of an Intent-Based Networking system.
Translate the operator's request into vendor-neutral traffic-policy intents.

Network knowledge base:
{kb}

Return ONLY a JSON object:
{{
  "intents": [
    {{
      "description": "<short restatement>",
      "action": "permit" | "deny",
      "source": {{"group": "<name>"}} | {{"host": "<name>"}} | {{"subnet": "<a.b.c.d/len>"}},
      "destination": same shape as source,
      "services": [{{"protocol": "ip"|"icmp"|"tcp"|"udp", "ports": [<int>, ...]}}],
      "bidirectional": <bool>,
      "priority": <1-1000, default 100>,
      "preferred_solution": null | "acl" | "firewall" | "vlan"
    }}
  ],
  "clarifications": ["<question>", ...]
}}

Rules:
- Use group/host names exactly as listed. Use "subnet" only for addresses given explicitly.
- "all traffic"/unspecified service => [{{"protocol": "ip", "ports": []}}]. ping => icmp.
  Map well-known apps to ports: http 80, https 443, ssh 22, telnet 23, dns udp 53, ftp 21, smtp 25, rdp 3389.
  "web" means tcp 80 and 443.
- "only X allowed" => a permit intent for X plus a deny intent for all ip, with the permit at higher priority.
- "between A and B", "isolate A from B", or "in both directions" => bidirectional true.
- Set preferred_solution only if the operator names a mechanism (ACL, firewall, VLAN).
- If an entity is unknown or the request is ambiguous (direction, service, which group),
  return "intents": [] and ask concise questions in "clarifications". Never guess names.
"""


@dataclass
class ParseResult:
    intents: list[dict[str, Any]] = field(default_factory=list)
    clarifications: list[str] = field(default_factory=list)


class LLMIntentParser:
    def __init__(self, provider: LLMProvider, kb: KnowledgeBase):
        self.provider = provider
        self.kb = kb
        self.history: list[dict[str, str]] = []

    def parse(self, text: str) -> ParseResult:
        self.history.append({"role": "user", "text": text})
        data = self.provider.generate_json(SYSTEM_PROMPT.format(kb=self.kb.llm_context()), self.history)
        self.history.append({"role": "model", "text": json.dumps(data)})
        return ParseResult(intents=list(data.get("intents") or []),
                           clarifications=list(data.get("clarifications") or []))

    def answer(self, answers: str) -> ParseResult:
        return self.parse(f"Answers to your questions: {answers}")


_APPS = {"https": ("tcp", 443), "http": ("tcp", 80), "ssh": ("tcp", 22), "telnet": ("tcp", 23),
         "dns": ("udp", 53), "ftp": ("tcp", 21), "smtp": ("tcp", 25), "rdp": ("tcp", 3389)}


class RuleBasedParser:
    """Deterministic keyword parser (no network). Good enough for simple one-line intents."""

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def parse(self, text: str) -> ParseResult:
        low = text.lower()
        names = [(m.start(), {"group": g}) for g in self.kb.groups
                 for m in re.finditer(rf"\b{re.escape(g.lower())}\b", low)]
        names += [(m.start(), {"host": h}) for h in self.kb.hosts
                  for m in re.finditer(rf"\b{re.escape(h.lower())}\b", low)]
        names += [(m.start(), {"subnet": m.group(0)})
                  for m in re.finditer(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", low)]
        names.sort(key=lambda x: x[0])
        if len(names) < 2:
            return ParseResult(clarifications=["Which source and destination (group, host or subnet)?"])

        if re.search(r"\b(block|deny|prevent|stop|isolate|drop|forbid)\b", low):
            action = "deny"
        elif re.search(r"\b(allow|permit|enable|grant)\b", low):
            action = "permit"
        else:
            return ParseResult(clarifications=["Should this traffic be permitted or denied?"])

        services = []
        for app, (proto, port) in _APPS.items():
            if re.search(rf"\b{app}\b", low):
                services.append({"protocol": proto, "ports": [port]})
        if re.search(r"\bweb\b", low):
            services.append({"protocol": "tcp", "ports": [80, 443]})
        for proto, port in re.findall(r"\b(tcp|udp)\s*(?:port\s*)?/?\s*(\d{1,5})\b", low):
            services.append({"protocol": proto, "ports": [int(port)]})
        if re.search(r"\b(ping|icmp)\b", low):
            services.append({"protocol": "icmp", "ports": []})
        if not services:
            services = [{"protocol": "ip", "ports": []}]

        solution = next((s for s in ("acl", "firewall", "vlan") if re.search(rf"\b{s}\b", low)), None)
        return ParseResult(intents=[{
            "description": text.strip(),
            "action": action,
            "source": names[0][1],
            "destination": names[1][1],
            "services": services,
            "bidirectional": bool(re.search(r"\b(between|isolate|both directions|each other)\b", low)),
            "preferred_solution": solution,
        }])
