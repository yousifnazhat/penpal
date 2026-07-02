# v1 Release Checklist

Use this before cutting the first public contributor-ready PenPal release.

## Required

- [ ] `python -m unittest discover -v` passes.
- [ ] `python -m penpal playbooks playbooks` passes.
- [ ] README quick start works from a clean clone.
- [ ] `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md` are present.
- [ ] GitHub CI runs tests and playbook validation.
- [ ] Community playbooks have safety flags and visible commands.
- [ ] PI integration remains read-only by default.
- [ ] Sensitive parameters and credential-like evidence are masked by default and covered by a contract fixture.
- [ ] Demo contract fixture protects context, evidence, and suggestion shapes.
- [ ] Playbook matched-signal metadata is covered by a contract fixture.
- [ ] CLI JSON outputs for context, evidence, and suggestions are covered by a contract fixture.

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
