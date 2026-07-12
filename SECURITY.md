# Security Policy

PenPal is intended for authorized red-team, lab, and owned-environment use.

## Reporting security issues

Use GitHub private vulnerability reporting when available, or contact the maintainer before publishing exploit details for PenPal itself. Do not include real engagement data, credentials, or target identifiers.

## Project safety expectations

- Commands must be visible and explainable.
- Configure engagement scope for real assessments; once configured, PenPal blocks targets that do not match it.
- Sensitive values must be masked by default.
- Store secret parameters by environment reference; plaintext-sensitive parameters remain a compatibility path only.
- Risky actions should require operator approval.
- Evidence-backed suggestions are preferred over autonomous execution.
- Direct C2 tasking, exploit execution, or autonomous credential use must stay behind explicit safety gates.
