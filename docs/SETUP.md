# Setup

PenPal is local-first. The deterministic core runs with Python; the intended v1 cockpit runs through PI. You need GitHub for the public contributor workflow.

## Local development

Use Python 3.11 or newer. If your shell exposes it as `python3`, substitute `python3` for `python` in the commands below.

```bash
git clone https://github.com/yousifnazhat/penpal.git
cd penpal
python -m unittest discover -v
python -m penpal playbooks playbooks
```

No API keys are required for the deterministic core. PI requires its own provider login for the conversational cockpit.

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

## PI cockpit workflow

Use the read-only PI extension in `examples/pi/` as the official v1 cockpit path.

Git clone/download does not auto-run installers. Run the repo bootstrap once to install or verify PI:

```bash
./scripts/setup-pi.sh
```

Log into a model provider from PI before testing the extension:

```bash
pi
/login
```

```bash
export PENPAL_CWD=/path/to/penpal
export PENPAL_WORKSPACE=penpal-workspace
pi -e ./examples/pi/penpal-extension.example.ts
```

Do not commit provider tokens or API keys. PI stores OAuth/API-key auth outside this repository.

Keep mutating tools disabled unless the operator approval flow is enabled and tested.

See `examples/pi/README.md` for forced-tool smoke tests that verify PI is using the PenPal extension.

## Not needed for v1

- C2 accounts
- exploit framework integrations
- cloud hosting
- PyPI/npm publishing accounts
- OpenAI API keys for the deterministic core
