from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
PYPI_PROJECT_NAME = "penpal-enum"
NPM_ADAPTER_NAME = "@yousif_nazhat/penpal-pi"
REQUIRED_FILES = (
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check PenPal release metadata and v1 files.")
    parser.add_argument("--tag", help="Expected Git tag, such as v1.0.0 or v1.0.0-rc.1.")
    args = parser.parse_args(argv)

    errors = release_errors(args.tag)
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print(f"release metadata valid for {python_version()}")
    return 0


def release_errors(expected_tag: str | None = None) -> list[str]:
    errors = [f"missing required file: {path}" for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    version = python_version()
    semver = semver_version(version)
    project_name = _match(ROOT / "pyproject.toml", r'^name = "([^"]+)"$')
    package_version = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))["version"]
    adapter_package = json.loads((ROOT / "packages" / "penpal-pi" / "package.json").read_text(encoding="utf-8"))
    adapter_version = adapter_package["version"]
    module_version = _match(ROOT / "penpal" / "__init__.py", r'^__version__ = "([^"]+)"$')

    if project_name != PYPI_PROJECT_NAME:
        errors.append(f"PyPI project name is {project_name}, expected {PYPI_PROJECT_NAME}")
    if module_version != version:
        errors.append(f"penpal.__version__ is {module_version}, expected {version}")
    if package_version != semver:
        errors.append(f"package.json version is {package_version}, expected {semver}")
    if adapter_version != semver:
        errors.append(f"PI adapter version is {adapter_version}, expected {semver}")
    if adapter_package["name"] != NPM_ADAPTER_NAME:
        errors.append(f"PI adapter name is {adapter_package['name']}, expected {NPM_ADAPTER_NAME}")
    if adapter_package.get("private") is True:
        errors.append("PI adapter is marked private")
    if adapter_package.get("publishConfig", {}).get("access") != "public":
        errors.append("PI adapter publish access is not public")
    if expected_tag and expected_tag != f"v{semver}":
        errors.append(f"tag is {expected_tag}, expected v{semver}")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{semver}]" not in changelog:
        errors.append(f"CHANGELOG.md has no {semver} entry")
    if not re.fullmatch(r"\d+\.\d+\.\d+", (ROOT / ".pi-version").read_text(encoding="utf-8").strip()):
        errors.append(".pi-version must contain an exact numeric version")
    return errors


def python_version() -> str:
    return _match(ROOT / "pyproject.toml", r'^version = "([^"]+)"$')


def semver_version(version: str) -> str:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", version)
    if not match:
        raise ValueError(f"unsupported Python version: {version}")
    base, prerelease, number = match.groups()
    labels = {"a": "alpha", "b": "beta", "rc": "rc"}
    return base if not prerelease else f"{base}-{labels[prerelease]}.{number}"


def _match(path: Path, pattern: str) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise ValueError(f"version not found in {path}")
    return match.group(1)


if __name__ == "__main__":
    raise SystemExit(main())
