# v1 Release Checklist

Use this before cutting the first public contributor-ready PenPal release.

## Required

- [x] `python -m unittest discover -v` passes.
- [x] `python -m penpal playbooks playbooks` passes.
- [x] README quick start works from a clean clone.
- [x] README and setup docs present PI as the intended v1 conversational cockpit.
- [x] `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md` are present.
- [x] GitHub CI runs tests and playbook validation.
- [x] Community playbooks have safety flags and visible commands.
- [x] PI integration remains read-only by default.
- [x] Sensitive parameters and credential-like evidence are masked by default and covered by a contract fixture.
- [x] Demo contract fixture protects context, evidence, and suggestion shapes.
- [x] Playbook matched-signal metadata is covered by a contract fixture.
- [x] CLI JSON outputs for context, evidence, and suggestions are covered by a contract fixture.
- [x] PI smoke matrix covers every shipped PI tool.
- [x] `docs/CONTRACTS.md` reflects the shipped harness contracts.
- [x] Playbook contributor template is valid but not loaded as a shipped playbook.

## Current Evidence

Last local verification: 2026-07-08.

- `python3 -m unittest discover -v`: 38 tests passed.
- `python3 -m penpal playbooks playbooks`: 4 valid playbooks, 0 invalid.
- README quick start passed from a fresh worktree copy with a new workspace.
- `.github/workflows/ci.yml` runs tests and playbook validation on Python 3.11.
- PI read-only smoke matrix passed with `--no-builtin-tools` for `penpal_playbooks_validate`, `penpal_context`, `penpal_suggest`, `penpal_evidence`, and `penpal_playbook_show`.
- PI default mutating-tool smoke confirmed `penpal_ingest` is unavailable unless `PENPAL_ENABLE_MUTATING_TOOLS=true`.
- PI mutating ingest smoke confirmed non-interactive rejection leaves evidence empty, while interactive approval shows the explicit `PenPal ingest approval` dialog and adds six deterministic evidence records.

Local note: this workstation exposes `python3` as Python 3.9.6 and has no `python3.11` on `PATH`; Python 3.11 proof comes from CI until a local 3.11 runtime is available.

## Manual smoke test

```bash
python -m penpal init 10.10.10.5 --name demo
python -m penpal playbooks playbooks
python -m penpal context demo --json
python -m penpal playbooks playbooks --show snmp-mail-remote
```

## Do not ship v1 if

- direct C2 tasking is enabled
- exploit execution is wired into PI
- credential reveal is automatic
- community playbooks can bypass operator approval
- context output leaks sensitive values by default
