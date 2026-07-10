# PenPal contracts

These contracts are the stable handoff between PenPal's deterministic core and agent harnesses such as PI and future MCP clients.

Do not change these casually. If a contract changes, update the contract fixture tests, PI smoke docs, and release checklist in the same PR.

## Stable contracts

| Contract | Producer | Consumer | Guardrail |
| --- | --- | --- | --- |
| `penpal-context-v1` | `python -m penpal context <target> --json` | PI, MCP, future UI | `tests/test_contracts.py` |
| Suggestion JSON | `python -m penpal suggest <target> --json` | PI, MCP, future UI | `tests/test_contracts.py`, `tests/test_cli.py` |
| Evidence JSON | `python -m penpal evidence <target> --json` | PI, MCP, future UI | masked by default; `tests/test_contracts.py`, `tests/test_cli.py`, `tests/test_api.py` |
| Playbook JSON | `playbooks/*.json` | core matcher, contributors | `tests/test_playbooks.py` |
| Playbook `matched_signals` | core matcher | PI explanations, operator citations | `tests/test_contracts.py` |
| Masked context output | `build_context(..., reveal_secrets=False)` | all default harness reads | `tests/test_contracts.py` |
| PI harness smoke | `node scripts/check-pi.mjs` | maintainers and contributors | provider-free offline CI on Linux and Windows |

## Workspace storage

Workspace JSON files carry explicit versioned `penpal-*` storage schemas. Files created before schema markers were introduced remain readable and gain the current schema on their next write. PenPal rejects unknown schema versions instead of guessing how to interpret them.

Parameter storage uses `penpal-parameters-v2`; v1 files remain readable and upgrade on their next write. Environment-backed items persist `env_var` instead of `value`, while the external `penpal-context-v1` parameter shape stays unchanged.

Compound updates are serialized within one `Workspace` instance, including the threaded local API. Multiple PenPal processes must not write to the same workspace concurrently.

An optional workspace-root `scope.json` uses `penpal-scope-v1`. Once present, exact host, CIDR, wildcard-domain, and exclusion rules are enforced whenever a target is created or used by a target operation. Exclusions take precedence.

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
- Environment-backed parameters never persist their resolved value and fail clearly if explicit substitution is requested while the variable is missing.
- Configured engagement scope is enforced in CLI and API target paths without a force bypass.
- Evidence reads and ingest responses mask credential-like values unless the operator explicitly requests revelation.
- The local API accepts pasted `body.text`, never arbitrary local file paths, and does not enable browser cross-origin access.
- The API defaults to loopback-only binding, caps JSON request bodies at 1 MiB, and does not expose internal exception details in `500` responses.
- Suggestions cite stored services, evidence, or playbook `matched_signals`.
- Commands stay visible to the operator.
- Mutating tools require operator approval.
- No C2 tasking, exploit execution, or autonomous credential use belongs in v1 contracts.
