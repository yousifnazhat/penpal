# PI example

This folder sketches a safe first PI integration for PenPal.

It uses PI custom tools to read PenPal's deterministic context and playbook data. It does not expose command execution, credential reveal, C2 tasking, or exploit delivery.

## Files

- `penpal-extension.example.ts` — read-only PI extension example.
- `penpal-ingest-tool.example.ts` — disabled-by-default mutating ingest tool example.
- `OPERATOR_APPROVAL.md` — approval rules for future mutating tools.

## Usage sketch

Copy the example into a PI extension location, then point it at this repository:

```bash
export PENPAL_CWD=/path/to/penpal
export PENPAL_WORKSPACE=penpal-workspace
pi -e ./penpal-extension.example.ts
```

The extension exposes:

- `penpal_context`
- `penpal_suggest`
- `penpal_playbooks_validate`
- `penpal_playbook_show`

Keep the first integration read-only. `penpal-ingest-tool.example.ts` is intentionally not imported by the read-only extension. It also requires `PENPAL_ENABLE_MUTATING_TOOLS=true` and an operator confirmation before ingesting anything.

PI extension primitives used here follow the public PI extension docs: `ExtensionAPI`, `pi.registerTool`, and `typebox` schemas.
