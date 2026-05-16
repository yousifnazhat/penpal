# PenPal

Backend-first enumeration assistant for authorized pentesters.

PenPal is being designed as a product-quality tool, not just a lab script. The core idea is simple:

```text
services -> evidence -> parameters -> suggestions -> exact syntax -> more evidence
```

The first version focuses on the boring parts that make enumeration smoother:

- target workspaces with predictable folders
- dry-run scan planning
- optional Nmap execution
- Nmap XML parsing
- service summaries
- suggested next checks
- a tiny JSON API for a future frontend

## Quick Start

From this directory:

```powershell
python -m penpal init 10.10.10.5 --name nibbles
python -m penpal scan nibbles --profile quick
python -m penpal scan nibbles --profile quick --execute
python -m penpal parse-nmap nibbles .\penpal-workspace\targets\nibbles\scans\nmap\quick.xml
python -m penpal ingest nibbles --file .\snmpwalk.txt --source snmpwalk --service udp/161
python -m penpal evidence nibbles
python -m penpal params nibbles set community public
python -m penpal params nibbles set known_user daniel
python -m penpal params nibbles set known_password "Winter2024!" --sensitive
python -m penpal suggest nibbles
python -m penpal suggest nibbles --reveal-secrets
python -m penpal summary nibbles --write
python -m penpal serve
```

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
python -m penpal suggest nibbles --reveal-secrets
```

Sensitive values are stored locally in `parameters.json` and masked by default in output. Use `--reveal-secrets` only when you intentionally want complete command syntax printed.

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
python -m penpal summary <name> --write
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
- [Product Principles](docs/PRODUCT_PRINCIPLES.md)
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
