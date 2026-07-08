# Release Notes

## v0.1.0 Release Candidate

PenPal `0.1.0` is the first public contributor-ready release candidate. It keeps PenPal's deterministic Python core as the source of truth and uses PI as the intended conversational cockpit.

### User Path

```bash
git clone https://github.com/yousifnazhat/penpal.git
cd penpal
python -m unittest discover -v
python -m penpal playbooks playbooks
./scripts/setup-pi.sh
pi
```

On first PI launch, approve project-local files if prompted. Run `/login` inside PI if a provider is not configured.

### Included

- Local target workspaces, Nmap parsing, evidence ingest, masked context, deterministic suggestions, and Markdown summaries.
- Four validated community playbooks plus a contributor template.
- Source-backed eval cases and reviewed source facts for suggestion behavior.
- Service module planning for DNS, SMB, SNMP, and web checks without command execution.
- PI project package loading from `.pi/settings.json`, so normal PI startup can expose PenPal tools without `-e`.
- PI read-only tools for context, suggestions, evidence, playbooks, and service module plans.
- Disabled-by-default PI ingest tool with explicit operator approval.

### Safety Boundaries

- No direct C2 tasking.
- No exploit execution through PI.
- No autonomous credential use.
- Sensitive parameters and credential-like evidence stay masked by default.
- Mutating PI tools require explicit opt-in and operator approval.

### Pre-Tag Checks

```bash
python3 -m unittest discover -v
python3 -m penpal playbooks playbooks
./scripts/setup-pi.sh
git diff --check
```

Before tagging, run the clean-clone and release-archive smoke from [v1 Release Checklist](V1_RELEASE_CHECKLIST.md).
