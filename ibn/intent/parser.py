"""Natural language -> structured intent JSON.

`LLMIntentParser` grounds the LLM in the Knowledge Base and the deployed intents, and asks it to
return intents (including the enforcement mechanism it chose and why) or clarification questions.
`RuleBasedParser` is an offline fallback for tests and demos.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ibn.intent.llm import LLMProvider
from ibn.kb.knowledge_base import KnowledgeBase

SYSTEM_PROMPT = """You are the intent parser of an Intent-Based Networking system.
Translate the operator's request into vendor-neutral traffic-policy intents and decide how
each one is enforced.

Network knowledge base:
{kb}

Intents already deployed:
{deployed}

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
      "solution": "acl" | "firewall" | "vlan",
      "solution_reason": "<one or two sentences: why this mechanism fits>"
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
- Choose "solution" for every intent:
  * "acl": extended ACL on the router interface closest to the source. Stateless, smallest blast
    radius. The default for denying or filtering traffic between routed groups/subnets.
  * "firewall": Cisco zone-based firewall on the gateway router. Stateful (return traffic is handled
    automatically) but every routed interface of that router joins a zone. Prefer it for permits of
    specific services where stateful inspection matters, or when the operator asks for a firewall.
  * "vlan": move a host into an isolated VLAN. ONLY possible when denying ALL traffic ("ip") between
    two hosts on the same access switch and subnet. Never for routed groups such as HR <-> Finance.
  * If the operator names a mechanism, use it. Intents in one request that overlap must use the same
    solution, and so should a new intent that overrides an overlapping deployed intent (priority is
    only enforceable within one mechanism).
- If the system reports that your chosen solution failed translation or validation, read the
  errors, choose a different solution or adjust the intents, and return the complete JSON again.
- If an entity is unknown or the request is ambiguous (direction, service, which group),
  return "intents": [] and ask concise questions in "clarifications". Never guess names.
"""


@dataclass
class ParseResult:
    intents: list[dict[str, Any]] = field(default_factory=list)
    clarifications: list[str] = field(default_factory=list)


class LLMIntentParser:
    def __init__(self, provider: LLMProvider, kb: KnowledgeBase, deployed: list[str] | None = None):
        self.provider = provider
        self.kb = kb
        self.deployed = deployed or []
        self.history: list[dict[str, str]] = []

    def parse(self, text: str) -> ParseResult:
        self.history.append({"role": "user", "text": text})
        system = SYSTEM_PROMPT.format(kb=self.kb.llm_context(),
                                      deployed="\n".join(f"  - {d}" for d in self.deployed) or "  (none)")
        data = self.provider.generate_json(system, self.history)
        self.history.append({"role": "model", "text": json.dumps(data)})
        return ParseResult(intents=list(data.get("intents") or []),
                           clarifications=list(data.get("clarifications") or []))

    def answer(self, answers: str) -> ParseResult:
        return self.parse(f"Answers to your questions: {answers}")

    def rejected(self, errors: list[str]) -> ParseResult:
        """Validator -> LLM feedback: the chosen solution could not be translated or validated."""
        return self.parse("The Translation & Validation layer rejected your intents:\n- " + "\n- ".join(errors)
                          + "\nChoose a different solution or adjust the intents and return the complete JSON.")


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

        named = next((s for s in ("acl", "firewall", "vlan") if re.search(rf"\b{s}\b", low)), None)
        return ParseResult(intents=[{
            "description": text.strip(),
            "action": action,
            "source": names[0][1],
            "destination": names[1][1],
            "services": services,
            "bidirectional": bool(re.search(r"\b(between|isolate|both directions|each other)\b", low)),
            "solution": named or "acl",
            "solution_reason": f"named in the request ({named})" if named else "offline parser default (acl)",
        }])
