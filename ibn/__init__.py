"""Intent-Based Networking (IBN) framework.

Layers (see docs/architecture.md):
  web/          – Interface Layer: web GUI and JSON API
  intent/       – Intent Layer: the AI understands the request, then designs configuration (any technique)
  validation/   – Validation Layer: generic syntax, semantic, rollback, compliance, impact and AI review
  platforms/    – vendor modules: config parsing, grammar, data-plane model (Cisco IOS today)
  control/      – Control Layer: backup, staged rollout, verification, rollback, audit
  kb/           – shared Network Knowledge Base (inventory, topology, policies, state)
"""

__version__ = "0.2.0"
