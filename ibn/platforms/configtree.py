"""Hierarchical model of an indentation-based CLI config (Cisco IOS style; also fits EOS/NX-OS-like syntax).

`parse()` reads a running-config. `apply()` replays config-mode commands the way the device would:
entering existing modes, replacing single-value settings, and honouring `no ...` removals. That lets
the validator compute "config after the change" and "config after rollback" for any technique.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field

_SKIP = re.compile(r"^(!|Building configuration|Current configuration|configure terminal|conf t\b|version \S+$)")


@dataclass
class Node:
    text: str
    children: list["Node"] = field(default_factory=list)
    replaced_negation: bool = False  # "X" was applied over "no X": removing X restores "no X"

    def child(self, text: str) -> "Node | None":
        return next((c for c in self.children if c.text == text), None)

    def find(self, prefix: str) -> list["Node"]:
        return [c for c in self.children if c.text == prefix or c.text.startswith(prefix + " ")]

    def walk(self, depth: int = 0):
        for c in self.children:
            yield depth, c
            yield from c.walk(depth + 1)


def single_value_key(text: str) -> str | None:
    """Settings that replace their previous value instead of adding a new line."""
    t = text.split()
    if not t:
        return None
    if text.startswith("ip address ") and not text.endswith(" secondary"):
        return "ip address"
    if t[0] in ("description", "hostname", "encapsulation", "mtu", "bandwidth", "speed", "duplex") or \
            (t[0] == "name" and len(t) == 2):
        return t[0]
    for prefix in ("switchport access vlan", "switchport mode", "zone-member security",
                   "service-policy type inspect", "service-policy input", "service-policy output",
                   "tunnel source", "tunnel destination", "ip nat inside", "ip nat outside"):
        if text.startswith(prefix):
            return "ip nat" if prefix.startswith("ip nat") else prefix
    if text.startswith("ip access-group ") and len(t) == 4:
        return f"ip access-group {t[3]}"
    if re.match(r"^\d+ (permit|deny|remark|evaluate)\b", text):
        return f"seq {t[0]}"
    return None


class ConfigTree:
    def __init__(self) -> None:
        self.root = Node("")

    # ------------------------------------------------------------------ building
    @classmethod
    def parse(cls, text: str) -> "ConfigTree":
        tree = cls()
        tree._feed(text.splitlines(), apply_mode=False)
        return tree

    def copy(self) -> "ConfigTree":
        out = ConfigTree()
        out.root = copy.deepcopy(self.root)
        return out

    def apply(self, commands: list[str]) -> None:
        self._feed(commands, apply_mode=True)

    def _feed(self, lines: list[str], apply_mode: bool) -> None:
        stack: list[tuple[int, Node]] = []
        banner_end: str | None = None
        for raw in lines:
            line = raw.rstrip()
            if banner_end is not None:  # skip multi-line banner bodies
                if banner_end in line:
                    banner_end = None
                continue
            stripped = line.strip()
            if not stripped or _SKIP.match(stripped):
                continue
            if stripped == "end":
                stack.clear()
                continue
            if stripped == "exit":
                if stack:
                    stack.pop()
                continue
            indent = len(line) - len(line.lstrip(" "))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            parent = stack[-1][1] if stack else self.root
            if stripped.startswith("banner "):
                banner_end = _banner_delimiter(stripped)
            node = self._add(parent, stripped, apply_mode)
            if node is not None:
                stack.append((indent, node))

    @staticmethod
    def _add(parent: Node, text: str, apply_mode: bool) -> Node | None:
        if apply_mode and text.startswith("no "):
            target = text[3:]
            removed = [c for c in parent.children if c.text == target or c.text.startswith(target + " ")]
            parent.children = [c for c in parent.children if c not in removed]
            if (not removed or any(c.replaced_negation for c in removed)) and not parent.child(text):
                parent.children.append(Node(text))  # a negative setting, e.g. "no ip domain lookup"
            return None
        existing = parent.child(text)
        if existing:
            return existing
        replaced_negation = False
        if apply_mode:
            negated = parent.child("no " + text)
            if negated:
                parent.children.remove(negated)
                replaced_negation = True
        key = single_value_key(text)
        if key:
            for i, c in enumerate(parent.children):
                if single_value_key(c.text) == key:
                    parent.children[i] = Node(text, c.children if key.startswith("seq") else [])
                    return parent.children[i]
        node = Node(text, replaced_negation=replaced_negation)
        parent.children.append(node)
        return node

    # ------------------------------------------------------------------ reading
    def top(self, prefix: str) -> list[Node]:
        return self.root.find(prefix)

    def render(self) -> str:
        return "\n".join(" " * depth + node.text for depth, node in self.root.walk())

    def lines(self) -> set[str]:
        """Context-qualified lines, for diffs: 'interface Ethernet0/2 > ip access-group X in'."""
        out = set()

        def rec(node: Node, path: str) -> None:
            for c in node.children:
                full = f"{path} > {c.text}" if path else c.text
                out.add(full)
                rec(c, full)

        rec(self.root, "")
        return out


def _banner_delimiter(line: str) -> str | None:
    parts = line.split(maxsplit=2)
    if len(parts) < 3:
        return None
    body = parts[2]
    delim = body[:2] if body.startswith("^") else body[:1]
    return None if body.count(delim) >= 2 else delim


def diff(before: ConfigTree, after: ConfigTree) -> tuple[list[str], list[str]]:
    b, a = before.lines(), after.lines()
    return sorted(a - b), sorted(b - a)
