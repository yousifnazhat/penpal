from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .models import utc_now


SCOPE_SCHEMA = "penpal-scope-v1"
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ScopeError(ValueError):
    pass


class ScopeViolationError(ScopeError):
    pass


@dataclass(frozen=True)
class ScopeDecision:
    host: str
    allowed: bool
    matched_include: str | None
    matched_exclude: str | None
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "allowed": self.allowed,
            "matched_include": self.matched_include,
            "matched_exclude": self.matched_exclude,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class EngagementScope:
    includes: tuple[str, ...]
    excludes: tuple[str, ...]
    created_at: str
    updated_at: str

    @classmethod
    def from_rules(
        cls,
        includes: Iterable[str],
        excludes: Iterable[str] = (),
        *,
        created_at: str | None = None,
    ) -> "EngagementScope":
        normalized_includes = _normalize_rules(includes)
        if not normalized_includes:
            raise ScopeError("engagement scope requires at least one include rule")
        now = utc_now()
        return cls(
            includes=normalized_includes,
            excludes=_normalize_rules(excludes),
            created_at=created_at or now,
            updated_at=now,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementScope":
        schema = data.get("schema")
        if schema != SCOPE_SCHEMA:
            raise ScopeError(f"unsupported engagement scope schema: {schema}")

        includes = _stored_rules(data.get("includes"), "includes")
        excludes = _stored_rules(data.get("excludes", []), "excludes")
        scope = cls.from_rules(includes, excludes, created_at=str(data.get("created_at") or utc_now()))
        return cls(
            includes=scope.includes,
            excludes=scope.excludes,
            created_at=scope.created_at,
            updated_at=str(data.get("updated_at") or scope.updated_at),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": SCOPE_SCHEMA,
            "includes": list(self.includes),
            "excludes": list(self.excludes),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def evaluate(self, host: str) -> ScopeDecision:
        normalized_host = normalize_host(host)
        matched_include = next((rule for rule in self.includes if _rule_matches(normalized_host, rule)), None)
        matched_exclude = next((rule for rule in self.excludes if _rule_matches(normalized_host, rule)), None)

        if matched_exclude:
            return ScopeDecision(
                host=normalized_host,
                allowed=False,
                matched_include=matched_include,
                matched_exclude=matched_exclude,
                reason=f"excluded by {matched_exclude}",
            )
        if matched_include:
            return ScopeDecision(
                host=normalized_host,
                allowed=True,
                matched_include=matched_include,
                matched_exclude=None,
                reason=f"included by {matched_include}",
            )
        return ScopeDecision(
            host=normalized_host,
            allowed=False,
            matched_include=None,
            matched_exclude=None,
            reason="did not match an include rule",
        )


def normalize_host(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ScopeError("host must not be empty")
    if "*" in candidate or "/" in candidate:
        raise ScopeError(f"invalid target host: {value}")

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return _normalize_hostname(candidate)


def normalize_rule(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ScopeError("scope rules must not be empty")

    if candidate.startswith("*."):
        suffix = normalize_host(candidate[2:])
        try:
            ipaddress.ip_address(suffix)
        except ValueError:
            return f"*.{suffix}"
        raise ScopeError("wildcard scope rules require a hostname suffix")
    if "*" in candidate:
        raise ScopeError(f"invalid wildcard scope rule: {value}")
    if "/" in candidate:
        try:
            return ipaddress.ip_network(candidate, strict=False).with_prefixlen
        except ValueError as exc:
            raise ScopeError(f"invalid CIDR scope rule: {value}") from exc
    return normalize_host(candidate)


def _normalize_hostname(value: str) -> str:
    hostname = value.rstrip(".")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError(f"invalid hostname: {value}") from exc
    if not hostname or len(hostname) > 253:
        raise ScopeError(f"invalid hostname: {value}")
    if any(not HOST_LABEL_RE.fullmatch(label) for label in hostname.split(".")):
        raise ScopeError(f"invalid hostname: {value}")
    return hostname


def _normalize_rules(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ScopeError("scope rules must be provided as a list")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ScopeError("scope rules must be strings")
        rule = normalize_rule(value)
        if rule not in normalized:
            normalized.append(rule)
    return tuple(normalized)


def _stored_rules(value: object, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScopeError(f"scope.{key} must be a list of strings")
    return value


def _rule_matches(host: str, rule: str) -> bool:
    if rule.startswith("*."):
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return host.endswith(rule[1:])
    if "/" in rule:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(rule)
        except ValueError:
            return False
    return host == rule
