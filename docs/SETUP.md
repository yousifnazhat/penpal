# Setup

PenPal is local-first. The deterministic core runs with Python; the intended v1 cockpit runs through PI. You need GitHub for the public contributor workflow.

## Local development

Use Python 3.11 or newer. If your shell exposes it as `python3`, substitute `python3` for `python` in the commands below.

```bash
git clone https://github.com/yousifnazhat/penpal.git
cd penpal
python3 -m unittest discover -v
python3 -m penpal playbooks playbooks
```

No API keys are required for the deterministic core. PI requires its own provider login for the conversational cockpit.

## First smoke test

```bash
python3 -m penpal --workspace penpal-workspace init 10.10.10.5 --name demo --force
python3 -m penpal --workspace penpal-workspace parse-nmap demo examples/pi/demo-nmap.xml
python3 -m penpal --workspace penpal-workspace suggest demo
python3 -m penpal playbooks playbooks --show snmp-mail-remote
```

`penpal-workspace/` is ignored by Git. `context` output is masked by default and is the safest input for PI or another harness.

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

PenPal ships a project-local PI package setting in `.pi/settings.json`, so running `pi` from the repository root loads the PenPal extension after you approve project-local files. Do not commit provider tokens or API keys. PI stores OAuth/API-key auth outside this repository.

Once PI opens, try:

```text
Use PenPal to summarize target demo and recommend next checks.
```

Keep mutating tools disabled unless the operator approval flow is enabled and tested.

See `examples/pi/README.md` for forced-tool smoke tests that verify PI is using the PenPal extension.

## Local API safety

The JSON API binds to `127.0.0.1` by default and rejects non-loopback addresses. Request bodies are capped at 1 MiB, malformed bodies receive client errors, and sensitive values remain masked unless revelation is explicitly requested.

The `--allow-remote` flag overrides the bind guard for an isolated, trusted network. The API has no authentication or TLS, and remote clients can explicitly request unmasked values, so do not expose it to an untrusted LAN or the public internet.

## Not needed for v1

- C2 accounts
- exploit framework integrations
- cloud hosting
- PyPI/npm publishing accounts
- OpenAI API keys for the deterministic core
