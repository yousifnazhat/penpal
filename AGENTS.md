# Agent guidance for PenPal

PenPal is an authorized enumeration assistant. Keep the deterministic Python core as the source of truth; agent harnesses should read and explain PenPal data, not invent facts.

## Default workflow

1. Inspect the local checkout before changing anything.
2. Prefer the smallest useful diff.
3. Reuse existing CLI/API/playbook patterns before adding abstractions.
4. Run the smallest relevant checks before handing work back.
5. Summarize changed files, checks, safety notes, and the next best step.

## Safety boundaries

- Keep suggestions evidence-backed and commands visible.
- Mask sensitive parameters and credential-like evidence by default.
- Require operator approval for risky or credentialed actions.
- Do not add direct C2 tasking, exploit execution, hidden command execution, or autonomous credential use unless the maintainer explicitly asks for it.

## GitHub workflow

- Treat the local checkout as the source of truth for uncommitted work.
- Use GitHub for repository context, PRs, issues, CI status, and review follow-up.
- Do not use GitHub contents-file writes to bypass local git.
- Do not commit, push, or open PRs unless the maintainer explicitly asks.

## Useful checks

```bash
python -m unittest discover -v
python -m penpal playbooks playbooks
python -m penpal context demo --json
git diff --check
```
