# Service Modules

PenPal's service module layer turns discovered services into source-backed enumeration plans. It is the first step toward the product behavior we want: when a scan shows useful ports, PenPal should know which deterministic moves belong next, why they belong there, which parameters they need, and which professional source supports the command.

This layer is currently plan-only. It does not run commands or ingest output by itself yet.

## Current Modules

The initial registry covers four high-value enumeration areas:

- `snmp`: UDP SNMP checks, community-aware walking, and SNMP-focused Nmap scripts.
- `web`: HTTP script scans plus content and virtual-host discovery.
- `smb`: SMB script scans, null-session checks, and credential-aware share listing.
- `dns`: DNS script scans, zone-transfer checks, and broad record review.

Each planned command includes:

- `id`: stable command identifier for future automation and evidence tracking.
- `module`: service module name.
- `label`: human-readable action.
- `args`: exact command syntax as an argument list.
- `cwd`: target workspace directory.
- `service_key`: matched service such as `tcp/445` or `udp/161`.
- `source_tier`: highest-confidence source tier supporting the command.
- `sources`: source metadata, usually official docs first with internal notes where useful.

## Usage

Until this is wired into the main CLI, use the standalone helper:

```bash
python -m penpal.module_cli nibbles snmp
python -m penpal.module_cli nibbles web --json
python -m penpal.module_cli nibbles smb --reveal-secrets
```

The helper loads the target, services, and parameters from the workspace, then prints the planned commands. Sensitive parameters are masked by default. Use `--reveal-secrets` only when you intentionally want runnable commands with secret values rendered.

## Source Policy

Service modules are designed to operationalize PenPal's source policy:

1. Prefer official tool documentation for flags, syntax, and execution behavior.
2. Use professional methodology sources for workflow and sequencing.
3. Use internal course notes for learned paths and lab-specific intuition.
4. Use community references for idea generation only after marking them as lower confidence.

This first version mostly uses official tool docs, OWASP-style web methodology, and internal HTB/CPTS notes. MITRE ATT&CK is part of the broader product specification, but the current module model does not yet map every planned command to ATT&CK tactics or techniques. That mapping belongs in the next iteration.

## Next Iteration

The next stage should make modules first-class in the backend:

- Add `penpal modules list` and `penpal modules plan <target> <module>` to the main CLI.
- Attach module IDs and source metadata to suggestions.
- Add an execution path that can run a planned command, capture stdout/stderr, and store evidence.
- Add ATT&CK fields where relevant, especially for authenticated enumeration and Active Directory workflows.
- Add confidence scoring and preconditions so PenPal can choose the safest next move instead of only listing options.
- Sync the generated notes back into Obsidian-friendly markdown with evidence links.

The product goal is not simply a command cheat sheet. The goal is a compounding enumeration brain: scans become evidence, evidence unlocks parameters, parameters unlock stronger modules, and each recommendation stays traceable to a source.
