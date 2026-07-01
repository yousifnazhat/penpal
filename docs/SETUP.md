# Setup

PenPal is local-first. You need Python and GitHub for the public contributor workflow; PI is only needed when testing the agent harness.

## Local development

```bash
git clone https://github.com/yousifnazhat/penpal.git
cd penpal
python -m unittest discover -v
python -m penpal playbooks playbooks
```

No API keys are required for the deterministic core.

## First smoke test

```bash
python -m penpal init 10.10.10.5 --name demo
python -m penpal context demo --json
python -m penpal playbooks playbooks --show snmp-mail-remote
```

`context` output is masked by default and is the safest input for PI or another harness.

## GitHub workflow

Use GitHub for branches, issues, PRs, CI, and community contribution review.

Recommended loop:

```text
local change -> tests -> commit -> push branch -> draft PR -> CI -> review
```

Do not publish from automation unless the maintainer explicitly asks for a commit, push, or PR.

## PI workflow

Start with the read-only PI extension in `examples/pi/`.

```bash
export PENPAL_CWD=/path/to/penpal
export PENPAL_WORKSPACE=penpal-workspace
pi -e ./examples/pi/penpal-extension.example.ts
```

Keep mutating tools disabled until operator approval is implemented and tested.

## Not needed for v1

- C2 accounts
- exploit framework integrations
- cloud hosting
- PyPI/npm publishing accounts
- OpenAI API keys for the deterministic core
