# Intent-Based Networking (IBN)

Team: Heba, Asmaa, Ebraam, Menna

You type a business intent in a web page, for example *"HR may only reach the Finance web
server over HTTPS"*. IBN turns it into validated Cisco configuration, shows you every step,
asks for approval, deploys it in stages to the EVE-NG lab, checks the result, and rolls back
if anything fails.

```
 Web GUI ──► Intent Layer (Gemini) ──────────────► Validation Layer ──► Control Layer ──► EVE-NG
             understand → intent checks →          syntax · semantic ·   backup · apply ·
             design with ANY technique             rollback · compliance verify · rollback
             (ACL, firewall, VLAN, routing,        · impact · AI review
              NAT, QoS, ...)              ◄── rejected designs go back to the AI
                         └──────── Network Knowledge Base (kb/) ────────┘
```

Full design: [docs/architecture.md](docs/architecture.md).

## Start it

You need Python 3.10 or newer.

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e ".[dev]"
copy .env.example .env            # Windows  (Linux/macOS: cp); put GEMINI_API_KEY in it

ibn-web
```

Your browser opens **http://127.0.0.1:8000**. Press `Ctrl+C` in the terminal to stop the server.

## The web interface

| Page | What you do there |
|---|---|
| **New intent** | Type what you want and press **Analyze intent**. The AI asks if anything is unclear, then shows: (1) the structured intent with its **testable expectations**, (2) intent checks, (3) the **AI design** (approach, reasoning, risks, vendor-neutral model), (4) the config, rollback and verify commands per device, (5) the validation report, (6) the post-deployment checks. If the Validation Layer rejected a design, a yellow box shows what was wrong and that the AI fixed it. Then **Approve – dry run** or **Approve – deploy LIVE** |
| **Intents** | All intents, the technique the AI used, **Withdraw**, **Undo last deployment** |
| **Network** | Groups, hosts, devices, **Simulate a flow**, **Sync configs from devices**, and each device's current configuration as IBN sees it |
| **History** | Audit log with the exact commands sent |

**Limited verification:** when the AI uses something the built-in simulator cannot model (routing
changes, NAT, QoS, PBR, …), the page shows a yellow warning and the live button stays disabled
until you tick "I reviewed the AI-generated configuration".

**Gemini free tier:** each intent costs about 3 AI calls (understand, design, review), plus one per
redesign. The free tier allows only ~20 calls per day per model. Set `GEMINI_MODEL` to another
model (e.g. `gemini-flash-lite-latest`) when one runs out, or enable billing for real use.

## Connecting EVE-NG

1. The base lab must work first (addresses, GRE tunnel, routing: VPC4 can ping VPC5).
2. Add a **Management(Cloud0)** network to the lab and connect a spare port of every node to it
   (routers: `Ethernet0/3`; switches: `Ethernet0/3` as an access port in VLAN 99).
   Use free addresses in the same subnet as the EVE-NG VM (the IP you open EVE-NG with).
3. Enable SSH on every node:

```
! routers (R1 shown)
hostname R1
ip domain-name lab.local
username admin privilege 15 secret cisco123
enable secret cisco123
crypto key generate rsa modulus 2048
ip ssh version 2
line vty 0 4
 login local
 transport input ssh
interface Ethernet0/3
 description MGMT
 ip address 192.168.100.11 255.255.255.0
 no shutdown

! switches (SW1 shown): management in its own VLAN, never VLAN 1
hostname SW1
ip domain-name lab.local
username admin privilege 15 secret cisco123
enable secret cisco123
crypto key generate rsa modulus 2048
ip ssh version 2
line vty 0 4
 login local
 transport input ssh
vlan 99
 name MGMT
interface Ethernet0/3
 switchport mode access
 switchport access vlan 99
 no shutdown
interface Vlan99
 ip address 192.168.100.21 255.255.255.0
 no shutdown
```

4. In `kb/inventory.yaml` set each `host:` to the node's management IP (keep `interface:` as the
   management interface: IBN never changes it and leaves it out of simulations). Do not add the
   management ports to `topology.yaml`.
5. Put the credentials in `.env`, restart, and press **Sync configs from devices** on the Network page.

Quick alternative without a management network: use the EVE-NG telnet console of each node:
`mgmt: {host: <EVE-NG IP>, port: <console port>, transport: telnet}`.

## Settings (`.env`)

| variable | meaning |
|---|---|
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Intent Layer LLM |
| `IBN_USERNAME`, `IBN_PASSWORD`, `IBN_ENABLE_SECRET` | device login |
| `IBN_HOST`, `IBN_PORT` | where the web server listens (default `127.0.0.1:8000`). Keep it local: there is no login yet |
| `IBN_NO_BROWSER=1` | don't open the browser automatically |
| `BATFISH_HOST` | optional Batfish validation |

## For developers

* `ibn/web/app.py` – API under `/api/...` (interactive docs at `/docs`); `ibn/web/static/` – the page.
* `ibn/pipeline.py` – the flow; `ibn/intent/` – AI agent and intent checks; `ibn/validation/` – the
  generic validator and simulator; `ibn/platforms/` – vendor modules; `ibn/control/` – deployment.
* Guardrails (forbidden commands, protected subnets, object prefix, review blocking, attempts) are in
  `kb/policies.yaml`.
* **Adding a vendor:** write one `Platform` module in `ibn/platforms/` and set `platform:` in
  `kb/inventory.yaml`. The AI writes that vendor's syntax; the validator and control layer are shared.
* Tests use a scripted fake AI, so they need no API key: `pytest -q`
