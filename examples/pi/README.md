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
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
pi --version
pi
/login
```

```bash
export PENPAL_CWD=/path/to/penpal
export PENPAL_WORKSPACE=penpal-workspace
pi -e ./penpal-extension.example.ts
```

If `pi --list-models` says no models are available, finish `/login` before testing the extension.

The extension exposes:

- `penpal_context`
- `penpal_suggest`
- `penpal_playbooks_validate`
- `penpal_playbook_show`

## Read-only smoke tests

Run these from the repository root after PI login. `--no-builtin-tools` proves PI is using the PenPal extension tool, not shell fallback.

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_playbooks_validate -e ./examples/pi/penpal-extension.example.ts -p "Use the penpal_playbooks_validate tool once. Return only valid_playbooks and invalid_playbooks."
```

Expected:

```text
valid_playbooks: 4
invalid_playbooks: 0
```

Create a demo target with services:

```bash
python3 -m penpal --workspace penpal-workspace init 10.10.10.5 --name demo --force
python3 -m penpal --workspace penpal-workspace parse-nmap demo examples/pi/demo-nmap.xml
```

Then prove PI can read context and suggestions:

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_context -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_context for target demo once. Return the schema, target host, open services, suggestion titles, and any playbook matched_signals."
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_suggest -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_suggest for target demo once. Return the suggestion titles, reasons, and first command example for each. Do not invent anything."
```

Keep the first integration read-only. `penpal-ingest-tool.example.ts` is intentionally not imported by the read-only extension. It also requires `PENPAL_ENABLE_MUTATING_TOOLS=true` and an operator confirmation before ingesting anything.

PI extension primitives used here follow the public PI extension docs: `ExtensionAPI`, `pi.registerTool`, and `typebox` schemas.
