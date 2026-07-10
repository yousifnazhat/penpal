from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Evidence


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HOSTNAME_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
WEB_PATH_RE = re.compile(r"(?<![\w:/])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)+")
NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?P<state>open|filtered|open\|filtered)\s+(?P<service>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
USER_KV_RE = re.compile(
    r"\b(?:user(?:name)?|login|uid|account)\b\s*[:=]\s*['\"]?(?P<value>[A-Za-z][A-Za-z0-9._$@\\-]{1,63})",
    re.IGNORECASE,
)
PASSWORD_KV_RE = re.compile(
    r"\b(?:pass(?:word|wd)?|pwd)\b\s*[:=]\s*['\"]?(?P<value>[^\s'\";]{3,128})",
    re.IGNORECASE,
)
DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9_.-]+\\[A-Za-z][A-Za-z0-9._$-]{1,63}\b")
PASSWD_RE = re.compile(r"^(?P<value>[A-Za-z_][A-Za-z0-9_.-]{0,31}):x?:\d{1,6}:\d{1,6}:")
INTERESTING_FILE_RE = re.compile(
    r"(?i)(?:^|[\s\"'])(?P<value>[A-Za-z0-9_./\\-]*(?:config|backup|passwd|shadow|id_rsa|\.ssh|\.env|\.bak|\.old|\.zip|\.kdbx|web\.config|wp-config\.php)[A-Za-z0-9_./\\-]*)"
)
DOMAIN_HINT_KEYS = ("domain", "realm", "workgroup", "dns domain", "forest")
HOSTNAME_FILE_EXTENSIONS = (
    ".aspx",
    ".bak",
    ".conf",
    ".config",
    ".css",
    ".doc",
    ".docx",
    ".env",
    ".gif",
    ".html",
    ".jpg",
    ".js",
    ".json",
    ".kdbx",
    ".key",
    ".log",
    ".old",
    ".pdf",
    ".pem",
    ".php",
    ".png",
    ".svg",
    ".txt",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
)


@dataclass
class IngestResult:
    evidence: list[Evidence]
    ignored_duplicates: int = 0


def extract_evidence(
    text: str,
    source: str = "paste",
    service_key: str = "",
    existing_ids: set[str] | None = None,
) -> IngestResult:
    existing_ids = existing_ids or set()
    found: list[Evidence] = []
    seen: set[str] = set()

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        for match in NMAP_PORT_RE.finditer(line):
            value = f"{match.group('proto').lower()}/{match.group('port')} {match.group('service').lower()}"
            _add(found, seen, existing_ids, "service_hint", value, source, service_key, line, "high", line_no)

        for value in EMAIL_RE.findall(line):
            _add(found, seen, existing_ids, "email", value, source, service_key, line, "high", line_no)
            domain = value.split("@", 1)[1].lower()
            _add(found, seen, existing_ids, "domain", domain, source, service_key, line, "high", line_no)

        for value in URL_RE.findall(line):
            cleaned = value.rstrip(".,;)")
            _add(found, seen, existing_ids, "url", cleaned, source, service_key, line, "high", line_no)
            path = urlsplit(cleaned).path
            if path and path != "/":
                _add(found, seen, existing_ids, "web_path", path, source, service_key, line, "medium", line_no)

        for value in DOMAIN_USER_RE.findall(line):
            _add(found, seen, existing_ids, "username", value, source, service_key, line, "medium", line_no)

        passwd_match = PASSWD_RE.search(line)
        if passwd_match:
            _add(
                found,
                seen,
                existing_ids,
                "username",
                passwd_match.group("value"),
                source,
                service_key,
                line,
                "high",
                line_no,
            )

        for match in USER_KV_RE.finditer(line):
            _add(
                found,
                seen,
                existing_ids,
                "username",
                match.group("value"),
                source,
                service_key,
                line,
                "medium",
                line_no,
            )

        for match in PASSWORD_KV_RE.finditer(line):
            _add(
                found,
                seen,
                existing_ids,
                "credential_candidate",
                match.group("value"),
                source,
                service_key,
                line,
                "medium",
                line_no,
                tags=["sensitive"],
            )

        for match in INTERESTING_FILE_RE.finditer(line):
            value = match.group("value").strip("\"'")
            if value and value not in {".", "/"}:
                _add(found, seen, existing_ids, "interesting_file", value, source, service_key, line, "medium", line_no)

        for value in IP_RE.findall(line):
            _add(found, seen, existing_ids, "ip", value, source, service_key, line, "medium", line_no)

        for match in HOSTNAME_RE.finditer(line):
            lowered = match.group(0).lower().rstrip(".")
            previous = line[match.start() - 1] if match.start() > 0 else ""
            if previous in {"/", "\\", "@"}:
                continue
            if lowered.endswith(HOSTNAME_FILE_EXTENSIONS):
                continue
            evidence_type = "domain" if any(key in line.lower() for key in DOMAIN_HINT_KEYS) else "hostname"
            _add(found, seen, existing_ids, evidence_type, lowered, source, service_key, line, "medium", line_no)

        if looks_like_web_finding(line):
            for value in WEB_PATH_RE.findall(line):
                if len(value) > 1 and not value.startswith("//"):
                    _add(
                        found,
                        seen,
                        existing_ids,
                        "web_path",
                        value.rstrip(".,;"),
                        source,
                        service_key,
                        line,
                        "medium",
                        line_no,
                    )

    ignored = sum(1 for item in found if item.id in existing_ids)
    fresh = [item for item in found if item.id not in existing_ids]
    return IngestResult(evidence=fresh, ignored_duplicates=ignored)


def looks_like_web_finding(line: str) -> bool:
    lowered = line.lower()
    return any(
        token in lowered for token in ["status:", "code:", "http", "found", "redirect", "title", "words:", "size:"]
    )


def evidence_id(evidence_type: str, value: str, source: str, service_key: str) -> str:
    raw = "|".join([evidence_type.lower(), value.strip().lower(), source.strip().lower(), service_key.strip().lower()])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _add(
    found: list[Evidence],
    seen: set[str],
    existing_ids: set[str],
    evidence_type: str,
    value: str,
    source: str,
    service_key: str,
    context: str,
    confidence: str,
    line_no: int,
    tags: list[str] | None = None,
) -> None:
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return
    item_id = evidence_id(evidence_type, cleaned, source, service_key)
    if item_id in seen:
        return
    seen.add(item_id)
    found.append(
        Evidence(
            id=item_id,
            type=evidence_type,
            value=cleaned,
            source=source,
            service_key=service_key,
            context=context[:500],
            confidence=confidence,
            tags=tags or [],
            metadata={"line": line_no},
        )
    )
