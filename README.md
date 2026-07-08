# PenPal

Authorized enumeration assistant for pentesters, with PenPal as the deterministic core and PI as the intended conversational cockpit.

PenPal is being designed as a product-quality tool, not just a lab script. The core idea is simple:

```text
services -> evidence -> parameters -> suggestions -> exact syntax -> more evidence
```

The v1 product shape is:

```text
PenPal core -> PI cockpit -> operator-approved evidence loop
```

The CLI/API remain the source of truth for storage, parsing, masking, playbook matching, and deterministic suggestions. PI sits on top to explain what PenPal knows, rank next checks, ask for missing evidence, and keep the operator in control.

The first version focuses on the boring parts that make enumeration smoother:

- target workspaces with predictable folders
- dry-run scan planning
- optional Nmap execution
- Nmap XML parsing
- service summaries
- suggested next checks
- a tiny JSON API for a future frontend

## Quick Start

### PenPal core

From this directory:

Use Python 3.11 or newer. If your shell exposes it as `python3`, substitute `python3` for `python`.

```bash
python -m penpal init 10.10.10.5 --name nibbles
python -m penpal scan nibbles --profile quick
python -m penpal parse-nmap nibbles examples/pi/demo-nmap.xml
python -m penpal ingest nibbles --source snmpwalk --service udp/161 <<'EOF'
SNMPv2-MIB::sysName.0 = STRING: mail01.example.local
User: daniel
email: daniel@example.local
/backup.zip Status: 200, Size: 9001
EOF
python -m penpal evidence nibbles
python -m penpal params nibbles set community public
python -m penpal params nibbles set known_user daniel
python -m penpal params nibbles set known_password "Winter2024!" --sensitive
python -m penpal suggest nibbles
python -m penpal context nibbles --json
python -m penpal summary nibbles --write
python -m penpal playbooks playbooks
python -m penpal playbooks playbooks --show snmp-mail-remote
```

### PI cockpit

PI is the intended conversational layer for v1. After creating demo data, install or verify PI from the downloaded repository:

```bash
./scripts/setup-pi.sh
pi
```

Run `/login` inside PI if it asks for a provider login. On first launch, approve the project-local files when PI prompts; `.pi/settings.json` loads the PenPal PI package from this repository.

The setup script installs PI globally through npm as `@earendil-works/pi-coding-agent` when the `pi` command is missing. It never handles provider tokens or API keys. The PI extension reads the same masked PenPal context and suggestions as the CLI. Forced-tool smoke tests live in [PI Example](examples/pi/README.md).

Suggestions include copy-ready syntax with the target host filled in where possible. Values the tool cannot know yet stay explicit:

```text
Syntax:
- snmpwalk -v2c -c <community> 10.10.10.5
- curl --url "imap://10.10.10.5:143/INBOX" --user "<known_user>:<known_password>" --verbose
- xfreerdp /v:10.10.10.5 /u:<known_user> /p:<known_password> /cert:ignore
```

Credentialed examples use placeholders intentionally. Confirm credentials first, then replace `<known_user>` and `<known_password>`.

You can fill placeholders with target parameters:

```powershell
python -m penpal params nibbles set community public
python -m penpal params nibbles set known_user daniel
python -m penpal params nibbles set known_password "Winter2024!" --sensitive
python -m penpal params nibbles list
python -m penpal suggest nibbles

# Optional: intentionally print complete command syntax with sensitive values.
python -m penpal suggest nibbles --reveal-secrets
```

Sensitive values are stored locally in `parameters.json` and masked by default in output. Use `--reveal-secrets` only when you intentionally want complete command syntax printed.

For PI and future frontend integrations, `python -m penpal context <name> --json` returns a single masked snapshot of the target, services, evidence, parameters, deterministic suggestions, playbook match metadata, and Markdown summary.

By default, generated target data lives under:

```text
penpal-workspace/
  targets/
    nibbles/
      target.json
      services.json
      notes.md
      scans/
      jobs/
      loot/
      screenshots/
      web/
```

## Commands

```powershell
python -m penpal init <host> --name <name>
python -m penpal list
python -m penpal scan <name> --profile quick
python -m penpal scan <name> --profile version --execute
python -m penpal parse-nmap <name> <xml-path>
python -m penpal services <name>
python -m penpal ingest <name> --file <output.txt> --source <tool-name> --service <proto/port>
python -m penpal evidence <name>
python -m penpal params <name> list
python -m penpal params <name> set <key> <value>
python -m penpal params <name> unset <key>
python -m penpal suggest <name>
python -m penpal context <name> --json
python -m penpal summary <name> --write
python -m penpal playbooks <json-file-or-directory>
python -m penpal playbooks <json-file-or-directory> --show <playbook-id>
python -m penpal serve --host 127.0.0.1 --port 8765
```

Scan execution is opt-in. Without `--execute`, `scan` prints the commands it would run.

## API

The API is intentionally small and frontend-friendly:

- `GET /api/health`
- `GET /api/targets`
- `GET /api/targets/<name>`
- `GET /api/targets/<name>/services`
- `GET /api/targets/<name>/evidence`
- `GET /api/targets/<name>/parameters`
- `GET /api/targets/<name>/suggestions`
- `GET /api/targets/<name>/context`
- `GET /api/targets/<name>/summary`
- `POST /api/targets`
- `POST /api/targets/<name>/parse-nmap`
- `POST /api/targets/<name>/ingest`
- `POST /api/targets/<name>/parameters`

Example:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/targets
```

## Design Notes

This backend does not try to exploit targets or hide commands. It is meant to make authorized enumeration repeatable and visible.

For the product direction and architecture, see:

- [Architecture](docs/ARCHITECTURE.md)
- [Setup](docs/SETUP.md)
- [Harness Strategy](docs/HARNESS_STRATEGY.md)
- [MCP Adapter Plan](docs/MCP_ADAPTER.md)
- [Product Principles](docs/PRODUCT_PRINCIPLES.md)
- [PI Adapter Contract](docs/PI_ADAPTER.md)
- [PI Example](examples/pi/README.md)
- [Playbook Authoring](playbooks/README.md)
- [Release Notes](docs/RELEASE_NOTES.md)
- [v1 Release Checklist](docs/V1_RELEASE_CHECKLIST.md)
- [Roadmap](docs/ROADMAP.md)
- [Intelligence Loop](docs/INTELLIGENCE_LOOP.md)
- [Source Policy](docs/SOURCE_POLICY.md)
- [Source Registry](docs/SOURCE_REGISTRY.md)

## Paste-to-Evidence

Raw command output can be ingested from a file or pipe:

```powershell
python -m penpal ingest nibbles --file .\snmpwalk.txt --source snmpwalk --service udp/161
Get-Content .\ferox.txt | python -m penpal ingest nibbles --source feroxbuster --service tcp/80
```

The first extractor looks for high-signal items:

- usernames
- email addresses
- hostnames and domains
- URLs
- web paths
- interesting file names
- credential-looking strings
- plaintext Nmap-style service hints

It stores these in `evidence.json`, keeps source context, and prints deterministic suggestions when the evidence connects to discovered services.

## Community Playbooks

Community playbooks live in `playbooks/` as `penpal-playbook-v1` JSON files. They describe evidence-backed enumeration paths, required signals, visible commands, and safety flags. The first built-in examples cover SNMP-to-mail, HTTP vhosts, SMB share review, and AD context.

Valid playbooks are loaded by `suggest` and matched against recorded services and evidence. Matching playbooks become normal deterministic suggestions with visible commands.

In JSON output, playbook-backed suggestions include `metadata.matched_signals` so an agent or frontend can explain exactly why the playbook fired.

Validate them before contributing:

```powershell
python -m penpal playbooks playbooks
python -m penpal playbooks playbooks --show http-vhosts-hidden-apps
python -m unittest discover -v
```
