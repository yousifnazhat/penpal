from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SOURCE_SEEDS_SCHEMA = "penpal-source-seeds-v1"
SOURCE_FETCH_SCHEMA = "penpal-source-fetch-v1"
SOURCE_FACTS_SCHEMA = "penpal-reviewed-source-facts-v1"
DEFAULT_SEEDS_PATH = Path(__file__).resolve().parents[1] / "docs" / "SOURCE_SEEDS.json"
DEFAULT_FACTS_PATH = Path(__file__).resolve().parents[1] / "docs" / "SOURCE_FACTS.json"
DEFAULT_CACHE_DIR = Path(".penpal-source-cache")
MAX_SOURCE_BYTES = 2_000_000
MAX_EXTRACTED_FACTS = 12
MAX_FACT_LENGTH = 240
MAX_REVIEWED_FACT_LENGTH = 280


@dataclass
class SourceFetchResult:
    source: dict[str, Any]
    url: str
    final_url: str
    status: int
    content_type: str
    byte_count: int
    cache_path: str
    facts: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SOURCE_FETCH_SCHEMA,
            "source": {
                "id": self.source["id"],
                "name": self.source["name"],
                "tier": self.source["tier"],
                "status": self.source["status"],
                "areas": list(self.source.get("areas", [])),
                "extract": list(self.source.get("extract", [])),
                "requires_verification": bool(self.source.get("requires_verification", False)),
            },
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "content_type": self.content_type,
            "bytes": self.byte_count,
            "cache_path": self.cache_path,
            "facts": self.facts,
        }


def load_source_seeds(path: str | Path = DEFAULT_SEEDS_PATH) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != SOURCE_SEEDS_SCHEMA:
        raise ValueError(f"expected source seed schema {SOURCE_SEEDS_SCHEMA}")
    seeds = data.get("seeds")
    if not isinstance(seeds, list):
        raise ValueError("source seeds must be a list")
    return seeds


def find_source_seed(source_id: str, path: str | Path = DEFAULT_SEEDS_PATH) -> dict[str, Any]:
    for seed in load_source_seeds(path):
        if seed.get("id") == source_id:
            return seed
    raise ValueError(f"source seed not found: {source_id}")


def load_reviewed_source_facts(
    path: str | Path = DEFAULT_FACTS_PATH,
    *,
    source_id: str | None = None,
) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != SOURCE_FACTS_SCHEMA:
        raise ValueError(f"expected source facts schema {SOURCE_FACTS_SCHEMA}")
    facts = data.get("facts")
    if not isinstance(facts, list):
        raise ValueError("source facts must be a list")

    reviewed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fact in facts:
        _validate_reviewed_fact(fact)
        if fact["id"] in seen:
            raise ValueError(f"duplicate source fact id: {fact['id']}")
        seen.add(fact["id"])
        if source_id is None or fact["source_id"] == source_id:
            reviewed.append(fact)
    return reviewed


def fetch_source_seed(
    source_id: str,
    *,
    url: str | None = None,
    seeds_path: str | Path = DEFAULT_SEEDS_PATH,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    timeout: int = 15,
    max_bytes: int = MAX_SOURCE_BYTES,
) -> SourceFetchResult:
    seed = find_source_seed(source_id, seeds_path)
    seed_urls = list(seed.get("seed_urls", []))
    if not seed_urls:
        raise ValueError(f"source seed has no URLs: {source_id}")
    target_url = url or seed_urls[0]
    if target_url not in seed_urls:
        raise ValueError(f"url is not listed for source seed {source_id}: {target_url}")
    _require_allowed_url(target_url, seed)

    request = Request(target_url, headers={"User-Agent": "PenPal source fetcher"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(max_bytes + 1)
            final_url = response.geturl()
            status = getattr(response, "status", 200)
            content_type = response.headers.get("Content-Type", "")
    except HTTPError as exc:
        raise ValueError(f"source fetch failed with HTTP {exc.code}: {target_url}") from exc
    except URLError as exc:
        raise ValueError(f"source fetch failed: {exc.reason}") from exc

    if len(raw) > max_bytes:
        raise ValueError(f"source response exceeds {max_bytes} bytes: {target_url}")
    _require_allowed_url(final_url, seed)

    cache_path = _cache_path(cache_dir, source_id, final_url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(raw)

    text = raw.decode(_charset(content_type), errors="replace")
    parsed = _parse_html(text)
    facts = [
        {"type": "source_seed", "value": str(seed["name"]), "source_url": final_url},
        {"type": "source_tier", "value": str(seed["tier"]), "source_url": final_url},
    ]
    if parsed.title:
        facts.append({"type": "page_title", "value": parsed.title, "source_url": final_url})
    facts.extend(_extract_candidate_facts(seed, parsed, final_url))

    return SourceFetchResult(
        source=seed,
        url=target_url,
        final_url=final_url,
        status=int(status),
        content_type=content_type,
        byte_count=len(raw),
        cache_path=str(cache_path),
        facts=facts,
    )


def _require_allowed_url(url: str, seed: dict[str, Any]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"source URL must use https: {url}")
    host = parsed.hostname or ""
    allowed_domains = seed.get("allowed_domains", [])
    if not any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains):
        raise ValueError(f"source URL host is not allowed for {seed.get('id')}: {host}")


def _validate_reviewed_fact(fact: Any) -> None:
    if not isinstance(fact, dict):
        raise ValueError("source fact must be an object")
    required = [
        "id",
        "source_id",
        "source_tier",
        "source_url",
        "fact_type",
        "summary",
        "review_status",
        "safety",
    ]
    for key in required:
        if not isinstance(fact.get(key), str) or not fact[key].strip():
            raise ValueError(f"source fact missing {key}")
    if fact["review_status"] != "reviewed":
        raise ValueError(f"source fact is not reviewed: {fact['id']}")
    if urlparse(fact["source_url"]).scheme != "https":
        raise ValueError(f"source fact URL must use https: {fact['id']}")
    if len(fact["summary"]) > MAX_REVIEWED_FACT_LENGTH:
        raise ValueError(f"source fact summary is too long: {fact['id']}")


def _cache_path(cache_dir: str | Path, source_id: str, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return Path(cache_dir) / source_id / f"{digest}.html"


def _charset(content_type: str) -> str:
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1] or "utf-8"
    return "utf-8"


def _parse_html(text: str) -> "_SourceHTMLParser":
    parser = _SourceHTMLParser()
    parser.feed(text[:200_000])
    parser.close()
    parser.title = _normalize_fact(parser.title)
    parser.headings = _unique(_normalize_fact(item) for item in parser.headings)
    parser.code_blocks = _unique(_normalize_fact(item) for item in parser.code_blocks)
    return parser


def _extract_candidate_facts(
    seed: dict[str, Any], parsed: "_SourceHTMLParser", source_url: str
) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    extraction_types = set(seed.get("extract", []))
    if extraction_types.intersection(
        {
            "workflow",
            "tool_workflow",
            "test_categories",
            "vulnerability_taxonomy",
            "terminology",
            "data_model",
            "defensive_context",
            "risk_model",
            "course_scope",
            "reporting_expectations",
        }
    ):
        for heading in parsed.headings:
            facts.append(_candidate_fact("workflow_heading", heading, source_url))
            if len(facts) >= MAX_EXTRACTED_FACTS:
                return facts

    if extraction_types.intersection({"command_syntax", "flags", "output_formats", "tool_inventory", "modules"}):
        for snippet in parsed.code_blocks:
            if _looks_like_command(snippet, seed):
                facts.append(_candidate_fact("command_syntax", snippet, source_url))
                if len(facts) >= MAX_EXTRACTED_FACTS:
                    return facts

    return facts


def _candidate_fact(fact_type: str, value: str, source_url: str) -> dict[str, str]:
    return {
        "type": fact_type,
        "value": value[:MAX_FACT_LENGTH],
        "source_url": source_url,
        "review_status": "candidate",
    }


def _looks_like_command(value: str, seed: dict[str, Any]) -> bool:
    lowered = value.lower().strip()
    command_names = {
        "nmap",
        "ffuf",
        "feroxbuster",
        "nxc",
        "netexec",
        "crackmapexec",
        "impacket",
        "python",
        "smbclient",
        "bloodhound",
    }
    source_id = str(seed.get("id", "")).lower()
    command_names.update(part for part in source_id.replace("_", "-").split("-") if part)
    return any(lowered == command or lowered.startswith(f"{command} ") for command in command_names)


def _normalize_fact(value: str) -> str:
    return " ".join(value.split())


def _unique(values: Any) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            results.append(value)
    return results


class _SourceHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.capture_tag = ""
        self.title = ""
        self.headings: list[str] = []
        self.code_blocks: list[str] = []
        self.current = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"title", "h1", "h2", "h3", "code", "pre"}:
            self.capture_tag = tag
            self.current = ""

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag != self.capture_tag:
            return
        value = _normalize_fact(self.current)
        if tag == "title":
            self.title = value
        elif tag in {"h1", "h2", "h3"} and value:
            self.headings.append(value)
        elif tag in {"code", "pre"} and value:
            self.code_blocks.append(value)
        self.capture_tag = ""
        self.current = ""

    def handle_data(self, data: str) -> None:
        if self.capture_tag:
            self.current += data
