from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


SENSITIVE_EVIDENCE_TOKENS = ("credential", "password", "secret", "token", "key", "hash")
ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ParameterResolutionError(ValueError):
    pass


def normalize_environment_variable_name(value: str) -> str:
    normalized = value.strip()
    if not normalized or not ENV_VAR_RE.fullmatch(normalized):
        raise ValueError(f"invalid environment variable name: {value}")
    return normalized


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Service:
    port: int
    protocol: str
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    def label(self) -> str:
        parts = [self.name or "unknown"]
        version_bits = " ".join(bit for bit in [self.product, self.version] if bit)
        if version_bits:
            parts.append(f"({version_bits})")
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "tunnel": self.tunnel,
            "scripts": dict(self.scripts),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Service":
        return cls(
            port=int(data["port"]),
            protocol=str(data.get("protocol", "tcp")),
            state=str(data.get("state", "open")),
            name=str(data.get("name", "")),
            product=str(data.get("product", "")),
            version=str(data.get("version", "")),
            extrainfo=str(data.get("extrainfo", "")),
            tunnel=str(data.get("tunnel", "")),
            scripts=dict(data.get("scripts", {})),
        )


@dataclass
class Target:
    name: str
    host: str
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": list(self.tags),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Target":
        return cls(
            name=str(data["name"]),
            host=str(data["host"]),
            created_at=str(data.get("created_at") or utc_now()),
            updated_at=str(data.get("updated_at") or utc_now()),
            tags=list(data.get("tags", [])),
            notes=str(data.get("notes", "")),
        )


@dataclass
class CommandSpec:
    id: str
    label: str
    args: list[str]
    cwd: str
    output_prefix: str | None = None
    parser: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "args": list(self.args),
            "cwd": self.cwd,
            "output_prefix": self.output_prefix,
            "parser": self.parser,
        }


@dataclass
class Evidence:
    id: str
    type: str
    value: str
    source: str
    created_at: str = field(default_factory=utc_now)
    confidence: str = "medium"
    service_key: str = ""
    context: str = ""
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def sensitive(self) -> bool:
        lowered = self.type.lower()
        return any(token in lowered for token in SENSITIVE_EVIDENCE_TOKENS)

    def to_dict(self, reveal: bool = True) -> dict[str, Any]:
        masked = self.sensitive and not reveal
        return {
            "id": self.id,
            "type": self.type,
            "value": "<sensitive>" if masked else self.value,
            "source": self.source,
            "created_at": self.created_at,
            "confidence": self.confidence,
            "service_key": self.service_key,
            "context": "<sensitive>" if masked and self.context else self.context,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            id=str(data["id"]),
            type=str(data["type"]),
            value=str(data["value"]),
            source=str(data.get("source", "")),
            created_at=str(data.get("created_at") or utc_now()),
            confidence=str(data.get("confidence", "medium")),
            service_key=str(data.get("service_key", "")),
            context=str(data.get("context", "")),
            tags=list(data.get("tags", [])),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class Parameter:
    name: str
    value: str
    sensitive: bool = False
    source: str = "manual"
    env_var: str = ""
    resolved: bool = True
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if self.env_var:
            self.env_var = normalize_environment_variable_name(self.env_var)
            self.sensitive = True

    def to_dict(self, reveal: bool = True) -> dict[str, Any]:
        if self.sensitive and not reveal:
            value = "<sensitive>"
        elif self.env_var and not self.resolved:
            value = "<missing>"
        else:
            value = self.value
        return {
            "name": self.name,
            "value": value,
            "sensitive": self.sensitive,
            "source": f"env:{self.env_var}" if self.env_var else self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_storage_dict(self) -> dict[str, Any]:
        data = {
            "name": self.name,
            "sensitive": self.sensitive,
            "source": self.source,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if self.env_var:
            data["env_var"] = self.env_var
        else:
            data["value"] = self.value
        return data

    def require_value(self) -> str:
        if self.env_var and not self.resolved:
            raise ParameterResolutionError(f"environment variable {self.env_var} is not set for parameter {self.name}")
        return self.value

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        environment: Mapping[str, str] | None = None,
    ) -> "Parameter":
        raw_env_var = data.get("env_var", "")
        if not isinstance(raw_env_var, str):
            raise ValueError("parameter.env_var must be a string")
        env_var = raw_env_var.strip()
        if "env_var" in data and not env_var:
            raise ValueError("parameter.env_var must not be empty")
        if env_var and "value" in data:
            raise ValueError(f"environment-backed parameter {data.get('name')} must not store a value")

        values = os.environ if environment is None else environment
        resolved = not env_var or env_var in values
        return cls(
            name=str(data["name"]),
            value=values.get(env_var, "") if env_var else str(data.get("value", "")),
            sensitive=True if env_var else bool(data.get("sensitive", False)),
            source=str(data.get("source", "manual")),
            env_var=env_var,
            resolved=resolved,
            created_at=str(data.get("created_at") or utc_now()),
            updated_at=str(data.get("updated_at") or utc_now()),
        )
