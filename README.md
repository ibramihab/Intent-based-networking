# Intent-Based Networking (IBN)

Team: Heba, Asmaa, Ebraam, Menna

You type a business intent, for example *"HR may only reach the Finance web server over HTTPS"*.
IBN turns it into validated Cisco configuration, asks for approval, deploys it in stages to the
EVE-NG lab, checks the result, and rolls back if anything fails.

```
 CLI (stand-in for Web UI) ──► Intent Layer ──► Translation & Validation ──► Control Layer ──► EVE-NG (Cisco IOL)
                                  │  Gemini        Selector → Generator ⇄ Validator   backup/apply/verify/rollback
                                  └──────────── Network Knowledge Base (kb/) ─────────────┘
```

Full design: [docs/architecture.md](docs/architecture.md).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # put GEMINI_API_KEY and the device credentials here (never commit .env)

ibn kb check                  # validate inventory/topology/policies
ibn plan  "block HR from reaching Finance on ssh"            # parse + translate + validate, no deploy
ibn submit "isolate HR and Finance completely"               # ... + approval + dry-run deploy
ibn submit "HR may only reach VPC5 over https" --live        # push to the EVE-NG devices
```

Without `GEMINI_API_KEY`, or with `--offline`, a keyword parser is used instead of the LLM.
That's handy for tests and for working without network access.

### Commands

| command | what it does |
|---|---|
| `ibn plan TEXT` | intent → structured intent → validation → solution choice → candidate config → validation report. Writes `artifacts/<plan-id>/` |
| `ibn submit TEXT [--live] [--solution acl\|firewall\|vlan]` | `plan`, then asks for approval, then deploys. Dry-run unless `--live` |
| `ibn deploy PLAN_ID [--live]` | deploy a plan you saved earlier |
| `ibn withdraw INTENT_ID [--live]` | remove an intent; the config is rebuilt without it |
| `ibn rollback PLAN_ID [--live]` | undo the last committed plan using its stored rollback commands |
| `ibn intents` / `ibn history` | intent status dashboard / audit log |
| `ibn simulate VPC4 VPC5 --proto tcp --port 80` | trace a flow through the current managed state |
| `ibn kb sync` | pull running configs into `kb/configs/`, used for collision checks and Batfish |

`--record-state` with a dry run records the intent as deployed even though no device was
touched. Use it to develop without the lab.

## Lab (EVE-NG) prerequisites

The topology in `kb/topology.yaml` matches the lab diagram: R1–R2–R3, an R1↔R3 GRE tunnel,
HR 10.0.1.0/24 behind R1/SW1 and Finance 10.0.3.0/24 behind R3/SW3.
For `--live`, every device needs management access from the machine running `ibn`:

```
! example for R1 – management via an EVE-NG cloud (pnet0) on a spare interface
hostname R1
ip domain-name lab.local
username admin privilege 15 secret <password>
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

Then put the management IPs in `kb/inventory.yaml`. If you only have the EVE-NG console, set
`transport: telnet` with the EVE host and the node's console port. Don't add the management
interface to `topology.yaml`.

## Adding another vendor

1. Implement `VendorDriver` in `ibn/translation/drivers/<platform>.py`. Use templates under
   `templates/<platform>/` and implement `render_transition`, `validate_syntax`,
   `verification_checks` and the ping helpers.
2. `register(...)` it in `ibn/translation/drivers/__init__.py`.
3. Set `platform: <platform>` on the device in `kb/inventory.yaml`.

Intents, the vendor-neutral model, the selector, the validator, the simulator and the deployer
stay the same. Netmiko already supports Junos, EOS, NX-OS and others. A NETCONF/YANG transport
can be added as another `DeviceConnection`.

## Tests

```bash
pytest -q
```
