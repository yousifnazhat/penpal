# Contributing to PenPal

PenPal is an authorized enumeration assistant. Contributions should make evidence-backed red-team enumeration clearer, safer, and more repeatable.

## Good first contributions

- Add or improve community playbooks in `playbooks/`.
- Add parser or extraction tests for real tool output.
- Improve deterministic suggestions in `penpal/advisor.py`.
- Improve docs that help operators understand why a path is suggested.

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
python -m penpal playbooks playbooks
python -m penpal playbooks playbooks --show snmp-mail-remote
python -m unittest discover -v
```

## Safety boundary

Do not contribute playbooks that hide commands, bypass operator approval, or assume authorization. PenPal can suggest high-probability avenues, but the operator owns scope and execution.
