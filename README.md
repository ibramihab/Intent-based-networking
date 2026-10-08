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

## Lab (EVE-NG) prerequisites for LIVE deployment

The topology in `kb/topology.yaml` matches the lab diagram: R1–R2–R3, an R1↔R3 GRE tunnel,
HR 10.0.1.0/24 behind R1/SW1 and Finance 10.0.3.0/24 behind R3/SW3.
Every device needs management access from the PC running IBN:

```
! example for R1 – management via an EVE-NG cloud (pnet0) on a spare interface
hostname R1
ip domain-name lab.local
username admin privilege 15 secret <password>
enable secret <secret>
crypto key generate rsa modulus 2048
ip ssh version 2
line vty 0 4
 login local
 transport input ssh
interface Ethernet0/3
 description MGMT
 ip address 192.168.100.11 255.255.255.0
 no shutdown
```

Then put the management IPs in `kb/inventory.yaml` and the credentials in `.env`, and press
**Sync configs from devices** on the Network page so the AI and the validator work from the real
running configs instead of the topology baseline. If you only
have the EVE-NG console, set `transport: telnet` with the EVE host and the node's console port.
Don't add the management interface to `topology.yaml`.

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
