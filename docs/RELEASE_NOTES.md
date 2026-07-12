# Release Notes

## v0.2.0-rc.1 Integrated PI Early Access

PenPal `0.2.0rc1` is the first release candidate that verifies the deterministic Python core, bundled PI conversational harness, and installable Python artifacts as one cross-platform product path.

### Install And Verify

From the release archive on macOS or Linux:

```bash
python3 -m pip install .
./scripts/setup-pi.sh
pi
```

On Windows, run `./scripts/setup-pi.ps1`. If PI is absent, the setup scripts install the exact tested release from `.pi-version`; if another version exists, they preserve it and run a compatibility smoke unless replacement is explicitly requested. `/penpal-status` verifies all seven read-only tools and the four bundled playbooks without requiring a provider or model.

### Product Hardening

- Enforced engagement include/exclude scope across CLI and API target creation.
- Added environment-backed secret parameters so values can be resolved at runtime without being persisted.
- Versioned workspace JSON schemas, atomic replacement, and concurrency-safe evidence updates.
- Hardened local API request types, body limits, errors, cache controls, and non-loopback binding safeguards.
- Preserved masking, visible commands, and operator approval boundaries.

### PI Integration

- Pinned and tested `@earendil-works/pi-coding-agent` `0.80.6` with Node.js `22.19.0` or newer.
- Added Bash and PowerShell setup paths that install PI when missing.
- Added an offline RPC smoke that proves project package discovery, command registration, and `/penpal-status` behavior.
- Added Linux and Windows PI CI coverage while keeping the Python core authoritative.

### Distribution

- Python wheel and source distribution artifacts now include the four validated playbooks.
- CI installs the built wheel in a clean environment outside the checkout and validates the default playbook path.
- Release artifacts are attached to this GitHub prerelease. PyPI and npm registry publication remain intentionally deferred until package ownership and publishing credentials are verified.

Stored `v0.1.x` workspaces remain compatible and are upgraded to current storage schemas on write.

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
