# Community playbooks

Playbooks are small JSON files that turn repeatable red-team reasoning into deterministic PenPal suggestions.

Start from `TEMPLATE.md`, not by editing an existing playbook in place.

Good playbooks:

- start from evidence PenPal can verify, such as an open service or extracted artifact
- explain why the path is worth checking
- keep every command visible
- use placeholders like `<target_host>`, `<target_name>`, `<known_user>`, and `<known_password>`
- require authorized use and operator approval

They should not include exploit delivery, direct C2 tasking, hidden execution, or automatic credential use.

## Required shape

Every file uses `schema: "penpal-playbook-v1"` and must include:

- `id`, `title`, `description`
- non-empty `tags`
- non-empty `signals`
- non-empty `actions`
- `safety.authorized_use_only: true`
- `safety.requires_operator_approval: true`

Supported signal types:

- `service`: one required port or service name
- `service_any`: at least one matching open port
- `evidence`: a matching extracted evidence type or value

Supported action risks:

- `passive`
- `normal`
- `aggressive`
- `approval_required`

## Fast validation

Run these before opening a PR:

```bash
python -m penpal playbooks playbooks
python -m penpal playbooks playbooks --show snmp-mail-remote
python -m unittest discover -v
```

If a playbook validates and produces a useful, evidence-backed suggestion, it is probably shaped correctly.
