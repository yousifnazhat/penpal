# PI Adapter Contract

PenPal should treat PI as an agentic harness around a deterministic source of truth, not as the source of truth itself.

The stable core contracts are tracked in [PenPal contracts](CONTRACTS.md).

## Role split

- PenPal owns stored facts, parsing, playbook matching, command syntax, masking, and deterministic suggestions.
- PI reads PenPal context, explains tradeoffs, asks for missing evidence, and helps the operator choose the next check.
- The operator owns scope, authorization, credential use, and execution.

## Default PI loop

1. Fetch a masked context snapshot.
2. Summarize what is known, unknown, and high-value.
3. Rank PenPal suggestions without inventing facts.
4. Show exact commands from PenPal suggestions.
5. Ask for operator approval before any command execution or credential reveal.
6. Feed new output back through `ingest`, then repeat.

## Read-only context

CLI:

```bash
python -m penpal context <target> --json
```

API:

```text
GET /api/targets/<target>/context
```

The context snapshot uses `schema: "penpal-context-v1"` and includes:

- `target`
- `services`
- `evidence`
- `parameters`
- `suggestions`
- `summary`

Sensitive parameters and credential-like evidence are masked by default. PI should not request `--reveal-secrets` or `reveal_secrets=true` unless the operator explicitly asks for it.

## Suggested PI tools

These read-only tools are enough for the first PI integration:

| Tool | Operation | Safety |
| --- | --- | --- |
| `penpal_context` | Read `penpal context <target> --json` | Safe default |
| `penpal_suggest` | Read `penpal suggest <target> --json` | Safe default |
| `penpal_evidence` | Read `penpal evidence <target> --json` | Safe default |
| `penpal_playbooks_validate` | Run `penpal playbooks playbooks` | Safe default |
| `penpal_playbook_show` | Inspect one playbook | Safe default |

The first mutating candidate is `penpal_ingest`, but only after PI has an explicit operator approval flow. See `examples/pi/OPERATOR_APPROVAL.md` and the disabled-by-default `examples/pi/penpal-ingest-tool.example.ts`.

Avoid exposing these to autonomous PI execution in v1:

- `scan --execute`
- credential reveal
- parameter writes for secrets
- C2 tasking
- exploit execution

## Agent rules

PI should:

- cite `supporting_facts` and `metadata.matched_signals` when explaining a recommendation
- distinguish confirmed evidence from hypotheses
- prefer high-value, low-risk suggestions first
- ask for missing values instead of inventing placeholders
- keep generated commands visible

PI should not:

- invent services, evidence, credentials, or scope
- hide commands behind vague actions
- execute credentialed checks without approval
- treat playbooks as proof of exploitability
- send tasks to C2 or implants in v1

## Minimal tool shape

```json
{
  "name": "penpal_context",
  "input": {
    "target": "chain"
  },
  "output": {
    "schema": "penpal-context-v1"
  }
}
```

Keep the first PI integration this boring. If the context contract becomes too slow or too large, add filters later.

See `examples/pi/` for a read-only PI extension sketch.
