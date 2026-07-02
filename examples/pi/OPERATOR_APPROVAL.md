# Operator approval for mutating PI tools

The first PI example is read-only. Mutating tools should wait until the approval flow is explicit and boring.

## Mutating tools

Treat these as mutating:

- `penpal_ingest`
- parameter writes
- `scan --execute`
- credential reveal
- any future C2 or exploit integration

## Approval prompt

Before a mutating tool runs, PI should show:

- target name
- workspace path
- exact PenPal command argv or API operation
- whether stored evidence, parameters, jobs, or files will change
- whether sensitive values may be revealed
- source of the input, such as operator paste, file path, or tool output
- bounded input size

The operator should approve the exact operation, not a vague category like "continue enumeration".

## Safe first mutating tool

The first candidate is `penpal_ingest`, because it only adds operator-provided output to evidence.

Minimum approval text:

```text
PenPal will ingest operator-provided text into target <target>.
Command argv: <argv>
Source: <source>
Service: <service or none>
Input bytes: <size>
This may add evidence and trigger new deterministic suggestions.
Approve?
```

## Still blocked for v1

Do not expose these as autonomous PI tools yet:

- `scan --execute`
- `--reveal-secrets`
- secret parameter writes
- C2 tasking
- exploit execution

Keep PI helpful, not sneaky.

`penpal-ingest-tool.example.ts` shows this pattern and stays disabled unless `PENPAL_ENABLE_MUTATING_TOOLS=true`.
