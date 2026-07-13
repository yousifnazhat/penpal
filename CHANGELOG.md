# Changelog

Notable changes follow Keep a Changelog and semantic versioning.

## [Unreleased]

## [1.0.0-rc.1] - 2026-07-12

### Changed

- Opened the V1 release-candidate cycle with frozen CLI, JSON, workspace, MCP, and PI integration contracts.
- Expanded the `0.1.x` workspace compatibility regression across target, service, evidence, and parameter storage.

## [0.2.0-rc.3] - 2026-07-12

### Fixed

- Show the effective PenPal workspace path in `/penpal-status` for checkout and npm PI adapters.
- Keep documented registry installs on stable transitive dependencies without requiring pip's global prerelease flag.

## [0.2.0-rc.2] - 2026-07-12

### Added

- V1 support, compatibility, deprecation, and security policies.
- Self-diagnosing `penpal doctor` command and automated release checks.
- Optional read-only MCP server with a stdio integration harness.
- Public npm PI adapter and beta feedback issue form.

### Changed

- Changed the Python distribution name to `penpal-enum` while preserving the `penpal` command.

## [0.2.0-rc.1] - 2026-07-12

### Added

- Cross-platform PI bootstrap pinned to PI 0.80.6.
- Engagement scope enforcement and environment-backed secret parameters.
- CI-built Python wheel and source distribution with bundled playbooks.

### Changed

- Hardened workspace schemas, atomic writes, concurrency behavior, and local API contracts.

### Security

- Preserved masked defaults, visible commands, loopback API binding, and operator approval boundaries.

## [0.1.1-rc.1] - 2026-07-10

### Changed

- Hardened persistence, extraction fixtures, API behavior, linting, and contributor checks.

## [0.1.0] - 2026-07-08

### Added

- Initial deterministic core, workspace, playbooks, CLI/API, and project-local PI cockpit.

[Unreleased]: https://github.com/yousifnazhat/penpal/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/yousifnazhat/penpal/releases/tag/v1.0.0-rc.1
[0.2.0-rc.3]: https://github.com/yousifnazhat/penpal/releases/tag/v0.2.0-rc.3
[0.2.0-rc.2]: https://github.com/yousifnazhat/penpal/releases/tag/v0.2.0-rc.2
[0.2.0-rc.1]: https://github.com/yousifnazhat/penpal/releases/tag/v0.2.0-rc.1
[0.1.1-rc.1]: https://github.com/yousifnazhat/penpal/releases/tag/v0.1.1-rc.1
[0.1.0]: https://github.com/yousifnazhat/penpal/releases/tag/v0.1.0
