# Intent-Based Networking (IBN)

Team: Heba, Asmaa, Ebraam, Menna

You type a business intent in a web page, for example *"HR may only reach the Finance web
server over HTTPS"*. IBN turns it into validated Cisco configuration, shows you every step,
asks for approval, deploys it in stages to the EVE-NG lab, checks the result, and rolls back
if anything fails.

```
 Web GUI ──► Intent Layer ──► Translation & Validation ──► Control Layer ──► EVE-NG (Cisco IOL)
               │  Gemini        Selector → Generator ⇄ Validator   backup/apply/verify/rollback
               └──────────── Network Knowledge Base (kb/) ─────────────┘
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
| **New intent** | Type the intent, or click an example, and press **Analyze intent**. If the AI needs more detail it asks you; type the answer. You then see the understood intent, the intent checks, why ACL/firewall/VLAN was chosen, the generated config for each router (with its rollback), the validation report, and the ping checks that will run. Finally **Approve – dry run** (touches nothing) or **Approve – deploy LIVE** |
| **Intents** | Dashboard of all intents and their status. **Withdraw** removes an intent; **Undo last deployment** rolls back the most recent one |
| **Network** | The knowledge base (groups, hosts, devices, consistency check), **Simulate a flow** to trace a packet, and **Sync configs from devices** |
| **History** | Audit log of every plan, deployment and rollback, including the exact commands sent |

Without `GEMINI_API_KEY` the page uses the offline keyword parser.
**Record dry run as deployed** lets you build up intents without the lab.

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

Then put the management IPs in `kb/inventory.yaml` and the credentials in `.env`. If you only
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

* The web backend is `ibn/web/app.py` (FastAPI JSON API under `/api/...`; interactive docs at
  `/docs`). The frontend is plain HTML/CSS/JS in `ibn/web/static/`, with no build step.
* The UI only calls `ibn/pipeline.py`. The layers underneath don't know a web page exists.
* **Adding a vendor:** implement `VendorDriver` in `ibn/translation/drivers/<platform>.py`
  (templates in `templates/<platform>/`), `register(...)` it in `drivers/__init__.py`, and set
  `platform:` in `kb/inventory.yaml`. Nothing else changes.
* Tests: `pytest -q`
