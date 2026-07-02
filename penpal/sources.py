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
DEFAULT_SEEDS_PATH = Path(__file__).resolve().parents[1] / "docs" / "SOURCE_SEEDS.json"
DEFAULT_CACHE_DIR = Path(".penpal-source-cache")
MAX_SOURCE_BYTES = 2_000_000


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
    title = _extract_title(text)
    facts = [
        {"type": "source_seed", "value": str(seed["name"]), "source_url": final_url},
        {"type": "source_tier", "value": str(seed["tier"]), "source_url": final_url},
    ]
    if title:
        facts.append({"type": "page_title", "value": title, "source_url": final_url})

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


def _cache_path(cache_dir: str | Path, source_id: str, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return Path(cache_dir) / source_id / f"{digest}.html"


def _charset(content_type: str) -> str:
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1] or "utf-8"
    return "utf-8"


def _extract_title(text: str) -> str:
    parser = _TitleParser()
    parser.feed(text[:200_000])
    return " ".join(parser.title.split())


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data
