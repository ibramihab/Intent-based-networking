"""Intent-Based Networking (IBN) framework.

Layers (see docs/architecture.md):
  intent/       – natural language -> structured, validated, conflict-free intent
  translation/  – vendor-neutral model + vendor drivers (the LLM picks the solution)
  validation/   – syntax, semantic, compliance, impact and simulation checks
  control/      – backup, staged rollout, verification, rollback, audit
  kb/           – shared Network Knowledge Base (inventory, topology, policies, state)
"""

__version__ = "0.1.0"
