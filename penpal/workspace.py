from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

from .models import Evidence, Parameter, Service, Target, utc_now
from .scope import EngagementScope, ScopeDecision, ScopeViolationError


DEFAULT_WORKSPACE = "penpal-workspace"
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
TARGET_STORAGE_SCHEMA = "penpal-target-v1"
SERVICES_STORAGE_SCHEMA = "penpal-services-v1"
EVIDENCE_STORAGE_SCHEMA = "penpal-evidence-v1"
PARAMETERS_STORAGE_SCHEMA = "penpal-parameters-v1"
JOB_STORAGE_SCHEMA = "penpal-job-v1"


class WorkspaceError(RuntimeError):
    pass


class TargetExistsError(WorkspaceError):
    pass


class TargetNotFoundError(WorkspaceError):
    pass


def safe_target_name(value: str) -> str:
    safe = SAFE_NAME_RE.sub("_", value.strip()).strip("._-")
    return safe or "target"


class Workspace:
    def __init__(self, root: str | Path = DEFAULT_WORKSPACE):
        self.root = Path(root)
        self.targets_dir = self.root / "targets"
        self._lock = threading.RLock()

    def ensure(self) -> None:
        self.targets_dir.mkdir(parents=True, exist_ok=True)

    def target_path(self, name: str) -> Path:
        return self.targets_dir / safe_target_name(name)

    def create_target(self, host: str, name: str | None = None, force: bool = False) -> Target:
        with self._lock:
            self._require_host_in_scope(host)
            self.ensure()
            target_name = safe_target_name(name or host)
            target_dir = self.target_path(target_name)
            if target_dir.exists() and not force:
                raise TargetExistsError(f"Target already exists: {target_name}")

            for child in [
                target_dir / "scans" / "nmap",
                target_dir / "jobs",
                target_dir / "loot",
                target_dir / "screenshots",
                target_dir / "web",
            ]:
                child.mkdir(parents=True, exist_ok=True)

            target = Target(name=target_name, host=host)
            self.save_target(target)
            self.save_services(target_name, [])
            self.save_evidence(target_name, [])
            self.save_parameters(
                target_name,
                {
                    "target_host": Parameter(name="target_host", value=host, source="target"),
                    "target_name": Parameter(name="target_name", value=target_name, source="target"),
                },
            )

            notes_path = target_dir / "notes.md"
            if not notes_path.exists():
                notes_path.write_text(f"# {target_name}\n\nHost: `{host}`\n\n", encoding="utf-8")

            return target

    def require_target(self, name: str) -> Target:
        path = self.target_path(name) / "target.json"
        if not path.exists():
            raise TargetNotFoundError(f"Unknown target: {name}")
        target = Target.from_dict(read_storage_json(path, TARGET_STORAGE_SCHEMA))
        self._require_host_in_scope(target.host)
        return target

    def save_target(self, target: Target) -> None:
        self._require_host_in_scope(target.host)
        self.ensure()
        target.updated_at = utc_now()
        target_dir = self.target_path(target.name)
        target_dir.mkdir(parents=True, exist_ok=True)
        data = target.to_dict()
        data["schema"] = TARGET_STORAGE_SCHEMA
        write_json(target_dir / "target.json", data)

    def list_targets(self) -> list[Target]:
        self.ensure()
        targets: list[Target] = []
        for path in sorted(self.targets_dir.glob("*/target.json")):
            targets.append(Target.from_dict(read_storage_json(path, TARGET_STORAGE_SCHEMA)))
        return targets

    def scope_path(self) -> Path:
        return self.root / "scope.json"

    def load_scope(self) -> EngagementScope | None:
        path = self.scope_path()
        if not path.exists():
            return None
        return EngagementScope.from_dict(read_json(path))

    def set_scope(self, includes: list[str], excludes: list[str] | None = None) -> EngagementScope:
        with self._lock:
            existing = self.load_scope()
            scope = EngagementScope.from_rules(
                includes,
                excludes or [],
                created_at=existing.created_at if existing else None,
            )
            self.ensure()
            write_json(self.scope_path(), scope.to_dict())
            return scope

    def clear_scope(self) -> bool:
        with self._lock:
            path = self.scope_path()
            existed = path.exists()
            path.unlink(missing_ok=True)
            return existed

    def evaluate_scope(self, host: str) -> ScopeDecision | None:
        scope = self.load_scope()
        return scope.evaluate(host) if scope else None

    def _require_host_in_scope(self, host: str) -> None:
        decision = self.evaluate_scope(host)
        if decision and not decision.allowed:
            raise ScopeViolationError(f"Target {host!r} is outside engagement scope: {decision.reason}")

    def services_path(self, name: str) -> Path:
        return self.target_path(name) / "services.json"

    def load_services(self, name: str) -> list[Service]:
        self.require_target(name)
        path = self.services_path(name)
        if not path.exists():
            return []
        data = read_storage_json(path, SERVICES_STORAGE_SCHEMA)
        return [Service.from_dict(item) for item in data.get("services", [])]

    def save_services(self, name: str, services: list[Service]) -> None:
        target = self.require_target(name)
        ordered = sorted(services, key=lambda svc: (svc.protocol, svc.port))
        write_json(
            self.services_path(name),
            {
                "schema": SERVICES_STORAGE_SCHEMA,
                "updated_at": utc_now(),
                "services": [service.to_dict() for service in ordered],
            },
        )
        self.save_target(target)

    def merge_services(self, name: str, parsed: list[Service]) -> list[Service]:
        with self._lock:
            merged = {service.key: service for service in self.load_services(name)}
            for service in parsed:
                merged[service.key] = service
            services = sorted(merged.values(), key=lambda svc: (svc.protocol, svc.port))
            self.save_services(name, services)
            return services

    def evidence_path(self, name: str) -> Path:
        return self.target_path(name) / "evidence.json"

    def load_evidence(self, name: str) -> list[Evidence]:
        self.require_target(name)
        path = self.evidence_path(name)
        if not path.exists():
            return []
        data = read_storage_json(path, EVIDENCE_STORAGE_SCHEMA)
        return [Evidence.from_dict(item) for item in data.get("evidence", [])]

    def save_evidence(self, name: str, evidence: list[Evidence]) -> None:
        target = self.require_target(name)
        ordered = sorted(evidence, key=lambda item: (item.created_at, item.type, item.value))
        write_json(
            self.evidence_path(name),
            {
                "schema": EVIDENCE_STORAGE_SCHEMA,
                "updated_at": utc_now(),
                "evidence": [item.to_dict() for item in ordered],
            },
        )
        self.save_target(target)

    def append_evidence(self, name: str, evidence: list[Evidence]) -> list[Evidence]:
        with self._lock:
            merged = {item.id: item for item in self.load_evidence(name)}
            for item in evidence:
                merged[item.id] = item
            saved = sorted(merged.values(), key=lambda item: (item.created_at, item.type, item.value))
            self.save_evidence(name, saved)
            return saved

    def parameters_path(self, name: str) -> Path:
        return self.target_path(name) / "parameters.json"

    def load_parameters(self, name: str) -> dict[str, Parameter]:
        self.require_target(name)
        path = self.parameters_path(name)
        if not path.exists():
            return {}
        data = read_storage_json(path, PARAMETERS_STORAGE_SCHEMA)
        return {item["name"]: Parameter.from_dict(item) for item in data.get("parameters", [])}

    def save_parameters(self, name: str, parameters: dict[str, Parameter]) -> None:
        target = self.require_target(name)
        ordered = sorted(parameters.values(), key=lambda item: item.name)
        write_json(
            self.parameters_path(name),
            {
                "schema": PARAMETERS_STORAGE_SCHEMA,
                "updated_at": utc_now(),
                "parameters": [item.to_dict(reveal=True) for item in ordered],
            },
        )
        self.save_target(target)

    def set_parameter(
        self,
        name: str,
        parameter_name: str,
        value: str,
        sensitive: bool = False,
        source: str = "manual",
    ) -> Parameter:
        with self._lock:
            parameters = self.load_parameters(name)
            existing = parameters.get(parameter_name)
            parameter = Parameter(
                name=parameter_name,
                value=value,
                sensitive=sensitive,
                source=source,
                created_at=existing.created_at if existing else utc_now(),
                updated_at=utc_now(),
            )
            parameters[parameter_name] = parameter
            self.save_parameters(name, parameters)
            return parameter

    def unset_parameter(self, name: str, parameter_name: str) -> bool:
        with self._lock:
            parameters = self.load_parameters(name)
            existed = parameter_name in parameters
            if existed:
                del parameters[parameter_name]
                self.save_parameters(name, parameters)
            return existed

    def append_job(self, name: str, job: dict[str, Any]) -> Path:
        with self._lock:
            target = self.require_target(name)
            job_id = safe_target_name(str(job.get("id") or utc_now().replace(":", "").replace("+", "Z")))
            job["id"] = job_id
            job["target"] = target.name
            job["host"] = target.host
            job["created_at"] = job.get("created_at") or utc_now()
            path = self.target_path(name) / "jobs" / f"{job_id}.json"
            data = dict(job)
            data["schema"] = JOB_STORAGE_SCHEMA
            write_json(path, data)
            return path


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_storage_json(path: Path, expected_schema: str) -> dict[str, Any]:
    data = read_json(path)
    schema = data.get("schema")
    if schema not in {None, expected_schema}:
        raise WorkspaceError(f"Unsupported storage schema in {path}: {schema}")
    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
