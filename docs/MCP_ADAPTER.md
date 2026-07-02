# MCP Adapter Plan

MCP should make PenPal portable across agent clients without making any client the source of truth.

MCP should reuse the stable contracts in [PenPal contracts](CONTRACTS.md) rather than introducing MCP-only shapes.

## Goal

Expose the same safe PenPal primitives that PI uses:

- read target context
- read deterministic suggestions
- validate playbooks
- inspect one playbook

Do not expose command execution, credential reveal, exploit execution, or C2 tasking through MCP in v1.

## First tools

| Tool | Backing command | Default safety |
| --- | --- | --- |
| `penpal_context` | `python -m penpal context <target> --json` | masked, read-only |
| `penpal_suggest` | `python -m penpal suggest <target> --json` | masked, read-only |
| `penpal_playbooks_validate` | `python -m penpal playbooks playbooks --json` | read-only |
| `penpal_playbook_show` | `python -m penpal playbooks playbooks --show <id> --json` | read-only |

## Later tools

`penpal_ingest` is the first mutating candidate, but only after:

- operator approval is visible in the client
- input size limits are enforced
- source labels are required
- the resulting evidence is re-read through `penpal_context`

## Contract rules

- PenPal stores facts; MCP clients only request or submit data.
- Return existing `penpal-context-v1` and suggestion JSON instead of inventing MCP-only schemas.
- Mask sensitive values unless the operator explicitly requests reveal through a reviewed flow.
- Keep errors boring: missing target, invalid playbook, invalid input, or unsupported operation.
- Prefer local stdio transport first; add remote transport only when there is a concrete deployment need.

## Not v1

- `scan --execute`
- `--reveal-secrets`
- parameter writes for secrets
- direct exploit tooling
- C2 or implant tasking
- Hermes or OpenClaw-specific behavior
