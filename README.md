# PenPal

PenPal is a local-first assistant for authorized enumeration. It turns services and tool output into stored evidence, clear next checks, and visible command syntax. The Python core is deterministic; PI is the optional conversational cockpit.

PenPal does not execute exploits, hide commands, use credentials automatically, or provide C2 tasking.

## Choose Your Path

### Run the demo with PI

Use this path when you want the conversational cockpit. Download a release archive or clone the repository. You need Python 3.11 or newer, Node.js 22.19 or newer, and npm.

```bash
git clone https://github.com/yousifnazhat/penpal.git
cd penpal
python3 -m penpal doctor
python3 -m penpal --workspace penpal-workspace scope set --include 10.10.10.5
python3 -m penpal --workspace penpal-workspace init 10.10.10.5 --name demo
python3 -m penpal --workspace penpal-workspace parse-nmap demo examples/pi/demo-nmap.xml
python3 -m penpal --workspace penpal-workspace suggest demo
./scripts/setup-pi.sh
pi
```

On Windows PowerShell, run `./scripts/setup-pi.ps1` instead. The setup scripts install the pinned PI version when it is missing, then verify the project package without using a model or provider credentials.

Inside PI, approve project-local files if prompted, run `/login` when a provider is not configured, then try:

```text
Use PenPal to summarize target demo and recommend next checks.
```

Run `/penpal-status` for a provider-free check that PI, PenPal, and the bundled playbooks are connected.

### Connect an MCP client

Use this path when your existing agent supports MCP rather than PI. Install the optional local server, then configure the client to start the shown command over stdio:

```bash
python3 -m pip install "penpal-enum[mcp]"
penpal --workspace penpal-workspace mcp
```

The MCP server has the same seven read-only workflows as the PI cockpit. It masks sensitive values and does not execute commands or modify your workspace.

### Use the Python core only

The core works without PI. Install it and create a target:

```bash
python3 -m pip install penpal-enum
penpal doctor
penpal init 10.10.10.5 --name demo
penpal parse-nmap demo ./scan.xml
penpal suggest demo
```

The release wheel and source archive also include the Python core and bundled playbooks. Until the optional PI adapter is published to npm, PI support requires the downloaded repository.

### Diagnose setup

```bash
penpal doctor
penpal doctor --json
```

Doctor checks the Python version, playbooks, workspace schemas, scope, plaintext sensitive parameters, missing environment variables, and PI status. It does not modify the workspace. Include the redacted JSON output in bug reports.

## What PenPal Does

- Stores scoped targets, services, evidence, parameters, notes, and jobs in a local workspace.
- Parses Nmap XML and ingests pasted or saved tool output.
- Masks credential-like evidence and sensitive parameters by default.
- Uses deterministic suggestions, service modules, and reviewed playbooks to explain the next authorized check.
- Uses environment references for secrets so values are not persisted in workspace JSON.
- Provides a loopback-only JSON API for local integrations.

## Everyday Commands

```text
penpal doctor
penpal init <host> --name <name>
penpal scope set --include <host-or-cidr> [--exclude <host-or-cidr>]
penpal parse-nmap <name> <nmap.xml>
penpal ingest <name> --file <output.txt> --source <tool-name> --service <proto/port>
penpal services <name>
penpal evidence <name>
penpal suggest <name>
penpal context <name> --json
penpal mcp
penpal playbooks playbooks
penpal modules list
penpal modules plan <name> <module>
```

`scan` prints commands by default. It runs them only with `--execute`. Use `params set-env` for passwords, tokens, and keys; `params set` keeps sensitive values in local plaintext for compatibility.

## Safety

Configure engagement scope before a real assessment. Keep the local API on its default loopback address. Review every suggested command and remain responsible for authorization. Playbooks require authorized use and operator approval.

## Help And Contributing

- [Support policy](SUPPORT.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Playbook template](playbooks/TEMPLATE.md)

Run the contributor checks with:

```bash
python3 -m pip install ".[dev]"
python3 scripts/check.py
```
