# Architecture

This document maps each layer of the team's diagram to the code.

| Diagram layer | Code | Status |
|---|---|---|
| Interface Layer (Web UI) | `ibn/web/` (FastAPI API + single-page GUI) on top of `ibn/pipeline.py` | done (authentication/RBAC still to do) |
| Intent Layer | `ibn/intent/` | done (Gemini + offline parser) |
| Translation & Validation Layer | `ibn/translation/`, `ibn/validation/` | **main focus** |
| Control Layer | `ibn/control/` | **main focus** |
| Infrastructure Layer | EVE-NG, Cisco IOL; described in `kb/inventory.yaml` | lab |
| Network Knowledge Base | `kb/*.yaml`, `ibn/kb/` | done |

## Flow

```
text ─► Gemini (KB + deployed intents in the prompt) ─► clarification questions? ─► JSON intents,
        each with the solution the LLM chose (acl / firewall / vlan) and its reason
     ─► schema check ─► semantic check ─► conflict check (vs deployed intents)
     ─► Config Generator (desired managed state → driver render + rollback)
     ─► Validator (syntax, semantic, compliance, impact, Batfish)
     ─► rejected? the errors go back to Gemini, which picks again (up to 2 rounds;
        the Validator → Generator arrow in the diagram)
     ─► package artifacts/<plan-id>/ (configs, rollback, reports, probes)
     ─► human approval
     ─► Deployer: per device (staged): backup → apply → check errors → verify running config
        ─► reachability probes ─► success: commit state | failure: roll back in reverse order
     ─► deployment report + audit log
```

## Intent Layer (`ibn/intent/`)

* `parser.py`: the system prompt includes the Knowledge Base (groups, hosts with their access
  switch, devices) and the intents already deployed, so the LLM can only refer to entities that
  exist and can stay consistent with what is running. It returns
  `{"intents": [...], "clarifications": [...]}`, and every intent carries `solution` and
  `solution_reason`. The prompt explains when each mechanism fits:
  * **acl**: the default for filtering between routed groups. Stateless; placed inbound on the
    interface closest to the source.
  * **firewall**: Cisco zone-based firewall. Stateful, so it suits permits of specific services
    where session tracking matters. Every routed interface of that router joins a zone.
  * **vlan**: only for denying all traffic between two hosts on the same access switch.

  Overlapping intents must use the same mechanism, because precedence only holds within one.
  The GUI shows the questions and sends the operator's answer back in the same conversation.
  If the JSON fails the schema, the errors are sent back to the LLM once for a repair.
* `llm.py`: `LLMProvider` protocol and a Gemini REST client that retries 429/5xx with
  backoff. Swapping in another LLM means writing one class.
* `validation.py`:
  * **syntax**: pydantic schema in `ibn/models/intent.py`: required fields, types, port
    ranges, ports only with tcp/udp
  * **semantic**: entities exist (names normalised to their KB spelling), source and
    destination don't overlap, and the guardrail is enforced: no denying traffic between
    protected infrastructure subnets
  * **conflicts**: traffic-space overlap against deployed intents and the rest of the same
    request. Opposite actions must be decided by priority or by specificity, using the same
    precedence function the generator uses. Otherwise it's an error, and the GUI offers to
    raise the new intent's priority.

## Translation (`ibn/translation/`)

There is no separate solution selector: the LLM chooses. The layer below makes sure the choice
is real:

* `generator.py` refuses a choice that cannot work, with a reason the LLM can act on: a VLAN
  for routed subnets or for specific services, an ACL/firewall for two hosts on one L2 segment
  (the traffic never crosses a router), or nowhere to enforce the rule. The Validator then rejects
  anything that is syntactically wrong, references something missing, uses a capability the
  device lacks, breaks another intent, or causes unexplained collateral changes. Either rejection
  is sent back to the LLM (`IBN.feedback` → `LLMIntentParser.rejected`).
* `generator.py` builds the vendor-neutral `DeviceState` (`ibn/models/netconfig.py`) for
  every device from **all** active intents plus the new ones. There is one ACL per
  interface/direction and one policy per zone pair, so intents add up instead of overwriting
  each other. Rules are ordered by priority, then specificity, then age.
* Changed objects get a new revision name (`IBN_E0_2_IN_R3`). The update order is: define
  the new object → rebind → delete the old one. This is hitless.
* `drivers/cisco_ios.py` renders the before→after transition with Jinja templates. The
  rollback is the after→before transition, so it is exact by construction.

## Validation (`ibn/validation/`)

| stage | checks |
|---|---|
| Syntax | every rendered line, config and rollback, matches the IOS grammar for what IBN emits. Addresses, wildcards (contiguous, no host bits), ports and VLAN ranges are checked too |
| Semantic | interfaces exist; references resolve (binding → ACL, zone-pair → zone); every routed interface is zoned; device capabilities; IP overlap / duplicates in the KB; VLAN reserved/range/collision; against synced running configs: ACL name collisions and an unmanaged ACL already on the interface |
| Intent compliance | the built-in simulator checks that every active intent, not just the new ones, behaves as the intent model says after the change |
| Impact analysis | simulates every endpoint pair × probe services before and after the change. Each changed flow must be explained by an intent that was added or withdrawn; anything else is reported as *collateral*. A change to infrastructure↔infrastructure traffic fails the guardrail |
| Simulation (Batfish) | optional. Runs `initIssues` and `undefinedReferences` on the synced running configs plus the candidate |

The simulator (`simulator.py`) follows the shortest L3 path between routers, so HR↔Finance
goes over the tunnel. It models IBN ACLs (inbound and outbound), ZBF zone-pair semantics
(zoned↔unzoned is dropped, intra-zone passes, class-default passes) and VLAN isolation.

## Control (`ibn/control/`)

* `connection.py`: Netmiko over SSH or telnet (EVE-NG console), plus a `DryRunConnection`.
  Credentials come from environment variables whose names are listed in the inventory.
* `deployer.py`: staged rollout, one device at a time, switches first and then routers
  (`deployment.stage_order`). Each device is backed up (`backups/<deployment>/<dev>.cfg`),
  configured, and its output checked for `% Invalid`/`% Incomplete`/…. The running config is
  then verified with driver `Check`s. After all devices, the reachability probes run. On any
  failure, every touched device is rolled back in reverse order and the rollback is verified.
* `verifier.py` picks the probes automatically. It searches router-sourced pings whose
  simulated result changes because of the deployment, for example R3 pinging VPC4 while the
  reply crosses the new R1 ACL, and adds one control ping that must keep working. Expected
  results come from the simulator.
* `audit.py`: JSON-lines audit log (`logs/audit.jsonl`). The deployment report is saved next
  to the plan.

## State

`kb/state/intents.json` holds the intent records and their status. `kb/state/managed.json`
holds what IBN currently owns on each device. Every plan records a fingerprint of this state,
and deploying a stale plan is refused.

## Known limitations / next steps

* Precedence between intents only holds within one mechanism. A high-priority ACL permit
  cannot override a ZBF drop of a lower-priority intent. The validator detects this and
  rejects the plan; the fix is to withdraw the overlapping intent or use the same solution
  (the LLM is told about deployed intents and asked to do the latter).
* Changing a ZBF zone-pair's policy is `no service-policy` + `service-policy` inside a single
  config session, which can drop packets for a very short moment.
* The simulator models what IBN manages, not dynamic routing or unmanaged ACLs. Batfish is
  the high-fidelity option.
* Next intent types: connectivity (static/OSPF/GRE selection), QoS. Next: telemetry
  (SNMP/syslog) feeding verification, and authentication/RBAC for the web UI.
