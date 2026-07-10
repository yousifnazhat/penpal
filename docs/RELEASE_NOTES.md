# Release Notes

## v0.1.1-rc.1 Hardened Early Access

PenPal `0.1.1rc1` is the recommended early-adopter checkpoint for the downloaded-repository workflow. It preserves the deterministic Python core and project-local PI cockpit while hardening user data, persistence, packaging, and contributor verification.

### Upgrade

Download or pull the new release and continue using the existing workspace. Stored `v0.1.0` workspaces remain compatible and require no migration.

Sensitive evidence is now masked by default in `evidence` and `ingest` output. Use `--reveal-secrets` only when intentionally displaying the underlying value.

### Security And Reliability

- Removed browser cross-origin access from the local API.
- Removed arbitrary local-file ingestion from the API; API callers submit bounded tool output as text.
- Masked credential-like evidence in API and CLI reads unless explicitly revealed.
- Replaced workspace JSON files atomically and preserved the previous file when replacement fails.
- Validated target existence before writing services, evidence, or parameters.
- Kept parsed Nmap service results in their persisted job record.

### Extraction Quality

- Added realistic feroxbuster, Nmap, SNMP, and configuration-noise fixtures.
- Corrected URL path extraction so `https://host/assets/app.js` records `/assets/app.js`, not a malformed host-prefixed path.

### Contributor Experience

- Added pinned Ruff linting and formatting.
- Added `make check` for lint, format, 53 unit tests, and playbook validation.
- Made Python package discovery explicit so `playbooks/` is not mistaken for a Python package.
- Added a documented, deliberately gated PI npm-package distribution plan.

### Current Distribution

The supported experience remains a clone or GitHub release archive:

```bash
python3 -m pip install ".[dev]"
make check
./scripts/setup-pi.sh
pi
```

No npm PI adapter or PyPI package is published in this release candidate.

### Safety Boundaries

- No direct C2 tasking.
- No exploit execution through PI.
- No autonomous credential use.
- Mutating PI tools remain disabled by default and require operator approval.

### Verify The Release

```bash
make check
npm pack --dry-run --json
./scripts/setup-pi.sh
```

Release and smoke evidence is tracked in [v1 Release Checklist](V1_RELEASE_CHECKLIST.md).
