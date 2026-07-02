# PenPal contracts

These contracts are the stable handoff between PenPal's deterministic core and agent harnesses such as PI and future MCP clients.

Do not change these casually. If a contract changes, update the contract fixture tests, PI smoke docs, and release checklist in the same PR.

## Stable contracts

| Contract | Producer | Consumer | Guardrail |
| --- | --- | --- | --- |
| `penpal-context-v1` | `python -m penpal context <target> --json` | PI, MCP, future UI | `tests/test_contracts.py` |
| Suggestion JSON | `python -m penpal suggest <target> --json` | PI, MCP, future UI | `tests/test_contracts.py`, `tests/test_cli.py` |
| Evidence JSON | `python -m penpal evidence <target> --json` | PI, MCP, future UI | `tests/test_contracts.py`, `tests/test_cli.py` |
| Playbook JSON | `playbooks/*.json` | core matcher, contributors | `tests/test_playbooks.py` |
| Playbook `matched_signals` | core matcher | PI explanations, operator citations | `tests/test_contracts.py` |
| Masked context output | `build_context(..., reveal_secrets=False)` | all default harness reads | `tests/test_contracts.py` |
| PI smoke commands | `examples/pi/README.md` | maintainers and contributors | manual pre-release smoke |

## Change rule

A contract PR should answer:

1. What consumer needs this change?
2. Is the old shape still accepted or intentionally broken?
3. Which fixture proves the new shape?
4. Which PI or future MCP smoke command proves the harness path?
5. Does the default output still mask sensitive values?

If the answer is unclear, keep the current contract.

## Safety invariants

- Default harness reads are masked.
- Suggestions cite stored services, evidence, or playbook `matched_signals`.
- Commands stay visible to the operator.
- Mutating tools require operator approval.
- No C2 tasking, exploit execution, or autonomous credential use belongs in v1 contracts.
