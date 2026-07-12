# Contributing to PenPal

PenPal is an authorized enumeration assistant. Contributions should make evidence-backed red-team enumeration clearer, safer, and more repeatable.

## Good first contributions

- Add or improve community playbooks in `playbooks/`.
- Add parser or extraction tests for real tool output.
- Improve deterministic suggestions in `penpal/advisor.py`.
- Improve docs that help operators understand why a path is suggested.

When changing ingest behavior, add realistic raw output and expected/forbidden evidence pairs under `tests/fixtures/ingest/`. This keeps false-positive regressions visible.

## Community playbooks

Playbooks are JSON files using `schema: "penpal-playbook-v1"`. Copy the fenced JSON from `playbooks/TEMPLATE.md` into a new `playbooks/<your-playbook-id>.json`, then edit the fields. See `playbooks/README.md` for authoring guidance and the supported signal/action fields.

Required fields:

- `id`, `title`, `description`
- `tags`
- `signals`
- `actions`
- `safety.authorized_use_only: true`
- `safety.requires_operator_approval: true`

Validate playbooks before opening a PR:

```bash
python3 -m pip install ".[dev]"
make check
python3 -m penpal playbooks playbooks --show snmp-mail-remote
```

Use `python3 scripts/check.py` instead of `make check` on systems without Make.

Public compatibility rules are documented in `SUPPORT.md`. Deprecate a v1 path before removing it unless an urgent security fix requires otherwise, and update `CHANGELOG.md` for user-visible behavior.

Changes to the PI package or extension must also pass the model-free offline harness check with the PI version pinned in `.pi-version`:

```bash
PI_FORCE_INSTALL=1 ./scripts/setup-pi.sh
make pi-check
```

## Safety boundary

Do not contribute playbooks that hide commands, bypass operator approval, or assume authorization. PenPal can suggest high-probability avenues, but the operator owns scope and execution.
