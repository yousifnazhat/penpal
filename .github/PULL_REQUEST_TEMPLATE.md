## Summary

-

## Type

- [ ] Deterministic suggestion/rule
- [ ] Community playbook
- [ ] Parser or evidence extraction
- [ ] PI/API integration
- [ ] Docs or contributor readiness

## Safety checklist

- [ ] Commands are visible and operator-approved.
- [ ] No direct C2 tasking, exploit execution, or autonomous credential use.
- [ ] Sensitive values stay masked by default.
- [ ] Playbooks include `authorized_use_only` and `requires_operator_approval`.

## Validation

- [ ] `python -m unittest discover -v`
- [ ] `python -m penpal playbooks playbooks`

## Notes

-
