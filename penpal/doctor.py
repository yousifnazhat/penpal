from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .playbooks import scan_playbooks
from .workspace import (
    EVIDENCE_STORAGE_SCHEMA,
    LEGACY_PARAMETERS_STORAGE_SCHEMAS,
    PARAMETERS_STORAGE_SCHEMA,
    SERVICES_STORAGE_SCHEMA,
    Workspace,
    WorkspaceError,
    read_storage_json,
)


DOCTOR_SCHEMA = "penpal-doctor-v1"
SUPPORTED_PYTHON_MIN = (3, 11)
SUPPORTED_PYTHON_MAX = (3, 13)


def build_doctor_report(workspace: Workspace) -> dict[str, Any]:
    checks = [_python_check(), _playbook_check(), _workspace_check(workspace), _pi_check()]
    if any(check["status"] == "error" for check in checks):
        status = "error"
    elif any(check["status"] == "warning" for check in checks):
        status = "warning"
    else:
        status = "ok"
    return {"schema": DOCTOR_SCHEMA, "status": status, "checks": checks}


def format_doctor_report(report: dict[str, Any]) -> str:
    lines = [f"PenPal doctor: {report['status']}"]
    lines.extend(f"[{check['status']}] {check['name']}: {check['message']}" for check in report["checks"])
    return "\n".join(lines)


def _python_check() -> dict[str, str]:
    current = sys.version_info[:2]
    supported = SUPPORTED_PYTHON_MIN <= current <= SUPPORTED_PYTHON_MAX
    return _check(
        "python",
        "ok" if supported else "error",
        f"{platform.python_version()} on {platform.system()} ({'supported' if supported else 'unsupported'})",
    )


def _playbook_check() -> dict[str, str]:
    try:
        report = scan_playbooks("playbooks")
    except ValueError as exc:
        return _check("playbooks", "error", str(exc))
    if report.errors or not report.valid_playbooks:
        return _check(
            "playbooks",
            "error",
            f"{report.valid_playbooks} valid, {len(report.errors)} invalid",
        )
    return _check("playbooks", "ok", f"{report.valid_playbooks} valid")


def _workspace_check(workspace: Workspace) -> dict[str, str]:
    if not workspace.root.exists():
        return _check("workspace", "warning", f"not created: {workspace.root}")
    if not workspace.targets_dir.exists():
        return _check("workspace", "warning", f"no targets directory: {workspace.targets_dir}")

    try:
        scope = workspace.load_scope()
        targets = workspace.list_targets()
        plaintext_sensitive = 0
        missing_environment = 0
        for target in targets:
            read_storage_json(workspace.services_path(target.name), SERVICES_STORAGE_SCHEMA)
            read_storage_json(workspace.evidence_path(target.name), EVIDENCE_STORAGE_SCHEMA)
            parameters = read_storage_json(
                workspace.parameters_path(target.name),
                PARAMETERS_STORAGE_SCHEMA,
                LEGACY_PARAMETERS_STORAGE_SCHEMAS,
            )
            plaintext_sensitive += sum(
                1
                for parameter in parameters.get("parameters", [])
                if parameter.get("sensitive") and parameter.get("value") and not parameter.get("env_var")
            )
            missing_environment += sum(
                1
                for parameter in parameters.get("parameters", [])
                if parameter.get("env_var") and parameter["env_var"] not in workspace.environment
            )
    except (OSError, ValueError, WorkspaceError) as exc:
        return _check("workspace", "error", f"validation failed: {exc}")

    warnings = []
    if scope is None:
        warnings.append("scope not enforced")
    if plaintext_sensitive:
        warnings.append(f"{plaintext_sensitive} plaintext sensitive parameter(s)")
    if missing_environment:
        warnings.append(f"{missing_environment} missing environment variable(s)")
    message = f"{len(targets)} target(s)"
    if warnings:
        return _check("workspace", "warning", f"{message}; {', '.join(warnings)}")
    return _check("workspace", "ok", f"{message}; scope enforced")


def _pi_check() -> dict[str, str]:
    command = shutil.which("pi")
    if not command:
        return _check("pi", "warning", "not installed; the Python core remains available")
    try:
        completed = subprocess.run(
            [command, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _check("pi", "error", f"version check failed: {exc}")
    if completed.returncode:
        return _check("pi", "error", "version check returned a non-zero status")

    version = completed.stdout.strip()
    pinned_path = Path(".pi-version")
    if not pinned_path.exists():
        return _check("pi", "ok", f"{version} installed")
    pinned = pinned_path.read_text(encoding="utf-8").strip()
    if version != pinned:
        return _check("pi", "warning", f"{version} installed; repository tested with {pinned}")
    return _check("pi", "ok", f"{version} installed and tested")


def _check(name: str, status: str, message: str) -> dict[str, str]:
    return {"name": name, "status": status, "message": message}
