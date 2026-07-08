# PI example

This folder contains the safe first PI cockpit integration for PenPal.

It uses PI custom tools to read PenPal's deterministic context and playbook data. PI provides the conversational layer; PenPal remains the source of truth. The default extension does not expose command execution, credential reveal, C2 tasking, or exploit delivery.

## Files

- `penpal-extension.example.ts` — read-only PI extension example.
- `penpal-ingest-tool.example.ts` — disabled-by-default mutating ingest tool example.
- `OPERATOR_APPROVAL.md` — approval rules for future mutating tools.

## Usage sketch

From the repository root, install or verify PI:

```bash
./scripts/setup-pi.sh
pi
```

Run `/login` inside PI if no provider is configured, and approve project-local files when PI prompts.

The repository `.pi/settings.json` loads the PenPal PI package automatically from the repo root. The explicit `-e ./examples/pi/penpal-extension.example.ts` form below remains useful for forced-tool smoke tests.

If `pi --list-models` says no models are available, finish `/login` before testing the extension.

The extension exposes:

- `penpal_context`
- `penpal_suggest`
- `penpal_evidence`
- `penpal_playbooks_validate`
- `penpal_playbook_show`
- `penpal_modules_list`
- `penpal_module_plan`

## Read-only smoke tests

Run these from the repository root after PI login. `--no-builtin-tools` proves PI is using the PenPal extension tool, not shell fallback.

| Tool | Mode | Expected proof |
| --- | --- | --- |
| `penpal_playbooks_validate` | forced, non-interactive | `4` valid playbooks and `0` invalid playbooks |
| `penpal_context` | forced, non-interactive | `penpal-context-v1`, demo host, open services, and matched signals |
| `penpal_suggest` | forced, non-interactive | deterministic suggestion titles, reasons, and command examples |
| `penpal_evidence` | forced, non-interactive | evidence count and evidence types after ingesting demo evidence |
| `penpal_playbook_show` | forced, non-interactive | `snmp-mail-remote` title, signals, and safety flags |
| `penpal_modules_list` | forced, non-interactive | module names `dns`, `smb`, `snmp`, and `web` |
| `penpal_module_plan` | forced, non-interactive | matched SNMP services, planned command IDs, cwd, and source metadata |

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_playbooks_validate -e ./examples/pi/penpal-extension.example.ts -p "Use the penpal_playbooks_validate tool once. Return only valid_playbooks and invalid_playbooks."
```

Expected:

```text
valid_playbooks: 4
invalid_playbooks: 0
```

Create a demo target with services and evidence:

```bash
python3 -m penpal --workspace penpal-workspace init 10.10.10.5 --name demo --force
python3 -m penpal --workspace penpal-workspace parse-nmap demo examples/pi/demo-nmap.xml
python3 -m penpal --workspace penpal-workspace ingest demo --source snmpwalk-smoke --service udp/161 --json <<'EOF'
SNMPv2-MIB::sysName.0 = STRING: mail01.example.local
User: daniel
email: daniel@example.local
/backup.zip Status: 200, Size: 9001
EOF
```

Then prove PI can read context and suggestions:

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_context -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_context for target demo once. Return the schema, target host, open services, suggestion titles, and any playbook matched_signals."
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_suggest -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_suggest for target demo once. Return the suggestion titles, reasons, and first command example for each. Do not invent anything."
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_evidence -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_evidence for target demo once. Return only the evidence count and evidence types."
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_playbook_show -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_playbook_show for id snmp-mail-remote once. Return only the title, signals, and safety flags."
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_modules_list -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_modules_list once. Return only module names and command counts."
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_module_plan -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_module_plan for target demo and module snmp once. Return only matched_services, command ids, first cwd, and source tiers."
```

Expected proof:

- `penpal_context`: `penpal-context-v1`, host `10.10.10.5`, three open services, SNMP/mail/remote suggestions, and playbook `matched_signals`.
- `penpal_suggest`: deterministic suggestion IDs including `path_snmp_mail_remote` and `playbook_snmp-mail-remote`.
- `penpal_evidence`: six evidence items with domain, email, hostname, interesting file, username, and web path types.
- `penpal_playbook_show`: `SNMP to mail to remote access`, three signals, and both safety flags set to true.
- `penpal_modules_list`: `dns`, `smb`, `snmp`, and `web`, each with source-backed command templates.
- `penpal_module_plan`: `matched_services: true` for `snmp`, command IDs `snmp-nmap-info`, `snmp-community-check`, and `snmp-walk`, with cwd under the target workspace and source tiers.

Keep the first integration read-only by default. `penpal_ingest` is registered only when `PENPAL_ENABLE_MUTATING_TOOLS=true`; it requires an operator confirmation, a non-empty source, and bounded input before ingesting anything.

Default mutating-tool proof:

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-workspace pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_ingest -e ./examples/pi/penpal-extension.example.ts -p "Try to use penpal_ingest for target demo once. Return only whether the tool is available."
```

Expected:

```text
Unavailable
```

## Mutating ingest smoke test

Use interactive PI for `penpal_ingest`; `pi -p` cannot approve the confirmation prompt and should reject the tool call.

Start with a clean smoke workspace:

```bash
rm -rf penpal-pi-ingest-smoke
python3 -m penpal --workspace penpal-pi-ingest-smoke init 10.10.10.5 --name demo --force
```

Non-interactive rejection proof:

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-pi-ingest-smoke PENPAL_ENABLE_MUTATING_TOOLS=true pi --provider openai-codex --model gpt-5.4-mini --no-session --no-builtin-tools --tools penpal_ingest -e ./examples/pi/penpal-extension.example.ts -p "Use penpal_ingest for target demo exactly once with source \"snmpwalk-smoke\", service \"udp/161\", and text exactly: User: daniel. Return only the tool result."
python3 -m penpal --workspace penpal-pi-ingest-smoke evidence demo --json
```

Expected:

```text
Operator rejected PenPal ingest.
```

The evidence JSON should remain empty:

```json
{
  "evidence": []
}
```

Interactive approval proof:

```bash
PENPAL_CWD="$PWD" PENPAL_WORKSPACE=penpal-pi-ingest-smoke PENPAL_ENABLE_MUTATING_TOOLS=true pi --provider openai-codex --model gpt-5.4-mini --no-builtin-tools --tools penpal_ingest -e ./examples/pi/penpal-extension.example.ts
```

Then ask PI:

```text
Use penpal_ingest for target demo exactly once with source "snmpwalk-smoke", service "udp/161", and text exactly:
SNMPv2-MIB::sysName.0 = STRING: mail01.example.local
User: daniel
email: daniel@example.local
/backup.zip Status: 200, Size: 9001
Return only added count, ignored_duplicates, and evidence types. Do not call any other tool.
```

Approve only after PI shows `PenPal ingest approval`, target, workspace, argv, source, service, input byte count, and Yes/No choices. Verify the mutation outside PI:

```bash
python3 -m penpal --workspace penpal-pi-ingest-smoke evidence demo --json
python3 -m penpal --workspace penpal-pi-ingest-smoke suggest demo --json
```

Expected proof:

- PI returns `added count: 6`, `ignored_duplicates: 0`, and evidence types `hostname`, `username`, `email`, `domain`, `interesting_file`, and `web_path`.
- PenPal CLI shows six stored evidence records from `snmpwalk-smoke` on `udp/161`.
- PenPal suggestions include `review_web_paths` and `review_interesting_files` for `/backup.zip`.

PI extension primitives used here follow the public PI extension docs: `ExtensionAPI`, `pi.registerTool`, and `typebox` schemas.
