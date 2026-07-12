# PenPal Support Policy

PenPal is a local-first open-source tool for authorized labs, assessments, and owned environments.

## Supported v1 environment

- Python 3.11, 3.12, and 3.13.
- Current GitHub-hosted Linux, macOS, and Windows runners.
- The PI version recorded in `.pi-version`; other PI versions are best-effort and must pass `scripts/check-pi.mjs`.
- Workspaces created by PenPal `0.1.x` and later.

The CLI and persisted workspace are the source of truth. PI is the supported conversational layer, but the Python core remains usable without PI.

## Compatibility promise

Patch releases fix defects without intentionally changing public contracts. Minor releases may add fields and commands while preserving existing v1 fields and workspace readers. A breaking CLI, JSON, playbook, or storage change requires a major release or a documented compatibility period.

Unknown workspace schema versions fail clearly instead of being guessed. Supported legacy schemas are upgraded on write.

## Deprecation policy

A public v1 feature is deprecated in release notes before removal. When practical, PenPal keeps the old path for at least one minor release and prints a replacement. Security fixes may remove unsafe behavior sooner and will explain the exception.

## Getting help

Use GitHub issues for reproducible bugs and feature requests. Include `penpal doctor --json`, the smallest safe reproduction, and redact target or credential data. Security issues should follow `SECURITY.md`.

Support is best-effort; the project does not guarantee response times.
