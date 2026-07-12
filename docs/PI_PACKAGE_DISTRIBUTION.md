# PI Package Distribution Plan

Status: Python wheel and source artifacts are built and smoke-tested in CI. PenPal does not publish to npm or PyPI yet.

## Current supported path

The repository root is a private PI package. `.pi/settings.json` loads it from the local checkout, and the extension runs the Python core and bundled playbooks from that same checkout. This is the supported downloaded-repository experience. `.pi-version` pins the tested PI release, while `scripts/check-pi.mjs` proves package discovery and extension registration offline.

The current `package.json` deliberately uses `penpal-pi@0.0.0` with `private: true`. It is not a candidate for publication as-is.

## Why registry publication waits

PI can install npm packages globally or project-locally, but PenPal's extension needs a compatible Python core, its playbooks, and an operator-owned workspace. A published npm package must not quietly put target data inside its installation directory or rely on a hidden clone of the repository.

`npm pack --dry-run --json` on 2026-07-09 confirmed that the current root manifest would ship CI configuration, documentation, tests, and the repository-local PI setting. That is useful evidence that the current root package is for local development, not distribution.

## Distribution shape

1. The Python `penpal` core is independently installable, versioned, and ships validated playbooks.
2. Publish a separate, scoped npm PI adapter package after the maintainer verifies ownership of the npm scope and package name.
3. Have the adapter run the installed Python core through an explicit Python executable configuration, with an operator-selected workspace outside the npm installation directory.
4. Keep the npm adapter and Python core on the same documented compatibility range. The adapter must fail clearly when the compatible core is absent.

The npm adapter should retain PI and `typebox` as peer dependencies, because PI provides those extension APIs. Third-party runtime packages belong in `dependencies` only when the adapter actually imports them.

## Required package changes before publishing

- Move the PI extension out of `examples/` into a distribution-specific package directory.
- Add a narrow npm `files` allowlist for only the extension, package metadata, license, and user documentation.
- Replace the repository-root fallback with explicit Python-core and workspace discovery.
- Select and verify a scoped npm name; do not assume the unscoped `penpal-pi` name is available or owned.
- Set a real adapter version and document its supported PenPal core range.
- Keep mutating tools disabled by default in the published adapter.

## Release gates

Before any npm publication, all of these must pass from a clean temporary directory:

```text
npm pack --dry-run
node scripts/check-pi.mjs
python -m pip install <published PenPal core version>
pi install -l npm:<verified scope>/<verified package>@<version>
pi --no-builtin-tools --tools penpal_context ...
```

The smoke must prove that PI loads the published adapter, the adapter reads a masked `penpal-context-v1` snapshot, the workspace is outside the npm package directory, and `penpal_ingest` remains unavailable unless explicitly enabled and approved.

PI package installation details are documented in the official [PI packages guide](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/packages.md).

## Next decision

Verify ownership and publishing credentials for a public PyPI project before enabling trusted publishing. Then select and verify a scoped npm adapter name. No registry publication should be simulated or performed with an unverified namespace.
