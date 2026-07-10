# v1 Release Checklist

Use this before cutting a public contributor-ready PenPal prerelease.

## Required

- [x] `python -m unittest discover -v` passes.
- [x] `python -m penpal playbooks playbooks` passes.
- [x] README quick start works from a clean clone.
- [x] README and setup docs present PI as the intended v1 conversational cockpit.
- [x] Downloaded repo includes a one-command PI install/verify bootstrap.
- [x] Fresh public clone PI cockpit smoke passes.
- [x] Project-local PI package loads the PenPal extension without an explicit `-e` flag.
- [x] `docs/RELEASE_NOTES.md` describes the current release candidate.
- [x] GitHub archive smoke passes for the `v0.1.0` release-candidate commit.
- [x] GitHub `v0.1.0` prerelease is published and release tarball contains the PI onboarding files.
- [x] `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md` are present.
- [x] GitHub CI runs tests and playbook validation.
- [x] Community playbooks have safety flags and visible commands.
- [x] PI integration remains read-only by default.
- [x] Sensitive parameters and credential-like evidence are masked by default and covered by a contract fixture.
- [x] Demo contract fixture protects context, evidence, and suggestion shapes.
- [x] Playbook matched-signal metadata is covered by a contract fixture.
- [x] CLI JSON outputs for context, evidence, and suggestions are covered by a contract fixture.
- [x] Service module planning is covered by CLI and module fixtures.
- [x] PI smoke matrix covers every shipped PI tool.
- [x] `docs/CONTRACTS.md` reflects the shipped harness contracts.
- [x] Playbook contributor template is valid but not loaded as a shipped playbook.

## Current Evidence

Last local verification: 2026-07-10.

- `make check`: Ruff lint/format passed, 53 tests passed, and 4 playbooks validated.
- `python3 -m penpal playbooks playbooks`: 4 valid playbooks, 0 invalid.
- GitHub CI passed on Python 3.11 for merge commit `a5a68f9`.
- `./scripts/setup-pi.sh`: verified the local PI command and printed the PenPal extension launch path.
- README quick start passed from a fresh worktree copy with a new workspace.
- Fresh public clone smoke passed: `./scripts/setup-pi.sh`, demo target creation, Nmap parse, evidence ingest, PI forced `penpal_context`, and PI forced `penpal_module_plan`.
- Project-local PI package smoke passed without `-e`: `pi --approve --no-builtin-tools --tools penpal_playbooks_validate` returned 4 valid playbooks, and `penpal_module_plan` returned SNMP command IDs for the demo target.
- GitHub archive smoke passed for `d586d11e4b0dd8f348184ba74d8affae16184059`: archive contained `.pi/settings.json`, `package.json`, `scripts/setup-pi.sh`, and `docs/RELEASE_NOTES.md`; `./scripts/setup-pi.sh`, unit tests, playbook validation, PI package `penpal_playbooks_validate`, and PI package `penpal_module_plan` passed from the unpacked archive.
- GitHub `v0.1.0` prerelease is published, and the release tarball contains `.pi/settings.json`, `package.json`, `scripts/setup-pi.sh`, and `docs/RELEASE_NOTES.md`.
- `.github/workflows/ci.yml` runs tests and playbook validation on Python 3.11.
- PI read-only smoke matrix passed with `--no-builtin-tools` for `penpal_playbooks_validate`, `penpal_context`, `penpal_suggest`, `penpal_evidence`, `penpal_playbook_show`, `penpal_modules_list`, and `penpal_module_plan`.
- PI default mutating-tool smoke confirmed `penpal_ingest` is unavailable unless `PENPAL_ENABLE_MUTATING_TOOLS=true`.
- PI mutating ingest smoke confirmed non-interactive rejection leaves evidence empty, while interactive approval shows the explicit `PenPal ingest approval` dialog and adds six deterministic evidence records.

Local note: this workstation exposes `python3` as Python 3.9.6 and has no `python3.11` on `PATH`; Python 3.11 proof comes from CI until a local 3.11 runtime is available.

## Release

- Package version: `0.1.1rc1`
- Tag: `v0.1.1-rc.1`
- GitHub Release: https://github.com/yousifnazhat/penpal/releases/tag/v0.1.1-rc.1
- Release notes: [Release Notes](RELEASE_NOTES.md)
- Next step: collect onboarding friction before expanding distribution or adapter surfaces.

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
