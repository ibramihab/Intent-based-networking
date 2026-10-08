# Architecture

| Diagram layer | Code |
|---|---|
| Interface Layer (Web UI) | `ibn/web/` – FastAPI JSON API + single-page GUI |
| Intent Layer | `ibn/intent/` – Gemini agent: understand → validate intent → design config (any technique) |
| Validation Layer | `ibn/validation/` + `ibn/platforms/` – generic checks of whatever the AI produced |
| Control Layer | `ibn/control/` – Netmiko, backup, staged rollout, verification, rollback, audit |
| Infrastructure Layer | EVE-NG, Cisco IOL; described in `kb/inventory.yaml` |
| Network Knowledge Base | `kb/*.yaml`, `ibn/kb/` – inventory, topology, policies, IBN's view of each device config |

## Flow

```
operator text
  └─► Intent Layer (Gemini)
        1. understand: structured intent = description, category, requirements, scope,
           testable expectations (src, dst, protocol, port, allow|deny), priority
           – ambiguous? → questions back to the operator
        2. intent checks (deterministic): schema, entities exist, guardrails,
           conflicts with deployed intents (overriding one needs confirmation)
        3. design: any technique → vendor-neutral model → device CLI + rollback + verify commands
  └─► Validation Layer (generic, technique-agnostic)
        structure · syntax · semantic · rollback · intent compliance · impact · AI review · Batfish
        rejected? → exact errors go back to the AI, which redesigns (max_design_attempts)
  └─► validated package artifacts/<plan-id>/ + report → human approval
  └─► Control Layer: per device (staged): backup → apply → command errors → AI verify commands
        → reachability probes → success: update IBN's view | failure: rollback in reverse order
  └─► deployment report + audit log
```

## Intent Layer (`ibn/intent/`)

* `agent.py` keeps two conversations with the LLM: *understand* (with the operator's answers)
  and *design* (with the Validation Layer's rejections). Prompts are in `prompts.py`.
* The design prompt receives the topology, every device's current configuration (IBN's view) and
  the deployed intents with the commands they own, so the AI can extend existing objects instead
  of conflicting with them (e.g. one ACL per interface direction).
* The AI may use **any technique**. It must return a vendor-neutral model, per-device commands,
  exact rollback commands and read-only verification commands, and name new objects with the
  `object_prefix` (default `IBN_`).
* `validation.py` checks the intent before any design: schema, entities, expectation endpoints,
  guardrails (no blocking between protected infrastructure subnets) and conflicts. A new
  expectation that contradicts a deployed intent needs the operator's explicit override.
* `llm.py`: provider interface + Gemini client (retries 429/5xx). Swap LLMs by adding a provider.

## Validation Layer (`ibn/validation/`, `ibn/platforms/`)

The key idea: the validator does not need to know which technique the AI chose. It parses the
configuration, applies it to IBN's view of each device (`ConfigTree`, which replays config-mode
commands the way IOS does), and checks the result.

| Stage | What it checks |
|---|---|
| Design structure | devices exist, platform supported, rollback present, verify commands read-only, neutral model present |
| Syntax | platform grammar (any IOS command: modes, indentation, ACL entries, addresses/wildcards/masks, ports, VLAN ids, interface names) + `forbidden_commands` guardrails |
| Semantic | interfaces exist; IP duplicates/overlap; a subnet reused on unconnected devices; VLAN reserved/range/collision; references (ACL, class-map, policy-map, zone, route-map, prefix-list, object-group, interface) defined; nothing deleted while still referenced; infrastructure interfaces not shut; naming prefix |
| Rollback check | config → apply commands → apply rollback must equal the original config |
| Intent compliance | every expectation (new **and** already deployed) simulated on the resulting config, with priority/specificity precedence |
| Impact analysis | all endpoint pairs × probe services simulated before/after; unexplained changes = collateral; infrastructure flows changing = error |
| AI review | an independent LLM review of the change; `error` findings block when `llm_review_blocking: true` |
| Batfish | optional: parse issues and undefined references on the full post-change configs |

**Simulator coverage.** The platform parser turns config into a vendor-neutral data-plane model
(`ibn/models/dataplane.py`): interface addresses/shutdown, ACLs (named, numbered, standard,
extended, port operators, sequence order), zone-based firewall, null routes, access VLANs.
Features outside that model (routing protocols, static next-hop routes, PBR, NAT, QoS,
object-groups, …) are reported as **limited verification**. They are not blocked, but the GUI
requires an explicit acknowledgement before a live deployment.

**Adding a vendor** = one module in `ibn/platforms/` implementing `Platform`: syntax check,
config → data-plane model, references, unmodeled features, baseline config, ping. Everything
else is shared.

## Control Layer (`ibn/control/`)

* Netmiko over SSH or telnet (EVE-NG console); a dry-run connection for testing.
* Staged rollout (switches, then routers), backup per device, command error detection, the AI's
  verify commands (refused unless read-only), simulator-chosen ping probes, reverse-order
  rollback on any failure, audit log, deployment report saved next to the plan.

## State

`kb/state/intents.json` holds intent records with the commands each intent deployed.
`kb/state/configs.json` holds IBN's view of every device. It starts from a synced running config
(`Sync configs from devices`) or a baseline rendered from the topology, and is updated by every
deployment, rollback and sync. Plans record a state fingerprint; stale plans are refused.
