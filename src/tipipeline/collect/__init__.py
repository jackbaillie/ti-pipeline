"""Fetch public intelligence sources and retain content-addressed document versions."""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser
import httpx
import trafilatura

from tipipeline.db import dumps, now_iso
from tipipeline.models import SourceConfig
from tipipeline.pipeline import Context

_TRACKING = {"fbclid", "gclid", "dclid", "mc_cid", "mc_eid", "ref", "ref_src", "ref_url", "referrer", "referral", "source", "sourceid", "source_id", "src"}


def canonicalize_url(url: str) -> str:
    """Remove tracking, fragments and insignificant URL spelling differences."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return url.strip()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    authority = host + (f":{port}" if port and (scheme, port) not in {("http", 80), ("https", 443)} else "")
    query = sorted((k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                   if not k.lower().startswith("utm_") and k.lower() not in _TRACKING)
    return urlunsplit((scheme, authority, parts.path.rstrip("/"), urlencode(query), ""))


class _PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        if tag in {"p", "div", "li", "br", "tr", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden - 1)
        if tag in {"p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _plain(html: str) -> str:
    parser = _PlainText()
    parser.feed(html)
    return "\n".join(" ".join(line.split()) for line in "".join(parser.parts).splitlines() if line.strip())


def _hash(text: str) -> str:
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


def _date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace(" UTC", "+00:00").replace("Z", "+00:00"))
        return dt.replace(tzinfo=UTC).isoformat(timespec="seconds") if dt.tzinfo is None else dt.astimezone(UTC).isoformat(timespec="seconds")
    except ValueError:
        return None


@dataclass
class Document:
    source_id: str
    tier: str
    kind: str
    url: str
    canonical_url: str
    title: str
    text: str
    published_at: str | None = None
    meta: dict = field(default_factory=dict)


def _threatfox_text(malware: str, entries: list[dict]) -> str:
    lines = [f"ThreatFox indicators for {malware}."]
    for entry in entries:
        lines.append(" | ".join(f"{key}: {entry.get(key)}" for key in (
            "ioc_type", "ioc", "threat_type", "confidence_level", "malware", "tags", "reference", "first_seen")))
    return "\n".join(lines)


def _store(ctx: Context, doc: Document) -> tuple[int, str]:
    old = ctx.db.execute("SELECT * FROM documents WHERE canonical_url = ?", (doc.canonical_url,)).fetchone()
    if old and doc.kind == "ioc_batch":
        # Sliding one-day API windows must not remove already collected indicators.
        prior = json.loads(old["meta_json"]).get("iocs", [])
        merged = {(i["ioc_type"], i["ioc"]): i for i in prior + doc.meta["iocs"]}
        doc.meta["iocs"] = [merged[key] for key in sorted(merged)]
        doc.text = _threatfox_text(doc.meta["malware"], doc.meta["iocs"])
    content_hash = _hash(doc.text)
    stamp = now_iso()
    if old:
        if old["content_hash"] == content_hash:
            # Same body: keep the version, but store corrected metadata. A new title or
            # date can change near-duplicate matching, so process re-checks the document.
            if (old["title"], old["published_at"]) != (doc.title, doc.published_at):
                ctx.db.execute("UPDATE documents SET title=?, published_at=?, processed_version=NULL WHERE id=?",
                               (doc.title, doc.published_at, old["id"]))
            if old["meta_json"] != dumps(doc.meta):
                ctx.db.execute("UPDATE documents SET meta_json = ? WHERE id = ?", (dumps(doc.meta), old["id"]))
            return old["id"], "unchanged"
        ctx.db.execute(
            "INSERT INTO document_versions (document_id, version, content_hash, title, text, collected_at) VALUES (?, ?, ?, ?, ?, ?)",
            (old["id"], old["version"], old["content_hash"], old["title"], old["text"], old["updated_at"]),
        )
        ctx.db.execute(
            "UPDATE documents SET title=?, text=?, content_hash=?, meta_json=?, published_at=?, version=version+1, updated_at=? WHERE id=?",
            (doc.title, doc.text, content_hash, dumps(doc.meta), doc.published_at, stamp, old["id"]),
        )
        return old["id"], "updated"
    cur = ctx.db.execute(
        """INSERT INTO documents (source_id, tier, kind, url, canonical_url, title, text, published_at,
           collected_at, updated_at, content_hash, meta_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (doc.source_id, doc.tier, doc.kind, doc.url, doc.canonical_url, doc.title, doc.text, doc.published_at, stamp, stamp, content_hash, dumps(doc.meta)),
    )
    return int(cur.lastrowid), "new"


def _extract(client: httpx.Client, url: str, fallback: str = "") -> tuple[str, str]:
    try:
        response = client.get(url)
        response.raise_for_status()
        text = trafilatura.extract(response.text, url=url, include_tables=True, include_comments=False) or ""
    except Exception:
        if not fallback:
            raise
        text = ""
    if len(text.strip()) < 500 and len(fallback) > len(text.strip()):
        return fallback, "feed"
    return text.strip(), "article"


def _rss(client: httpx.Client, source: SourceConfig, first: bool, known: dict, ctx: Context) -> tuple[int, list[Document], list[str]]:
    response = client.get(source.url)
    response.raise_for_status()
    feed = feedparser.parse(response.content)
    if not feed.get("version") or (feed.bozo and not feed.entries):
        raise ValueError(f"invalid RSS/Atom feed: {feed.get('bozo_exception', 'no feed version')}")
    items = []
    cutoff = datetime.now(UTC) - timedelta(days=ctx.settings.initial_lookback_days)
    for entry in feed.entries:
        parsed = entry.get("published_parsed") or entry.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(parsed), UTC) if parsed else None
        # Unknown dates cannot satisfy the first-run lookback requirement.
        if first and (published is None or published < cutoff):
            continue
        url = entry.get("link", "")
        if urlsplit(url).scheme.lower() not in {"http", "https"}:
            continue
        items.append((published, entry, url))
    items.sort(key=lambda item: item[0] or datetime.min.replace(tzinfo=UTC), reverse=True)
    docs = []
    errors = []
    for published, entry, url in items[:max(0, source.max_items)]:
        canonical = canonicalize_url(url)
        content = "\n".join(part.get("value", "") for part in entry.get("content", []))
        fallback = _plain(content or entry.get("summary", ""))
        signature = _hash(dumps({"title": entry.get("title", ""), "published": entry.get("published"),
                                 "updated": entry.get("updated"), "content": content, "summary": entry.get("summary", "")}))
        if known.get(canonical) == signature:
            continue
        try:
            text, text_source = _extract(client, url, fallback) if source.fetch_full_text else (fallback, "feed")
        except Exception as exc:
            ctx.log.warning("source %s article %s failed: %s", source.id, url, exc)
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
            continue
        if not text.strip():
            ctx.log.warning("source %s article %s has no usable text", source.id, url)
            errors.append(f"{url}: no usable article or feed text")
            continue
        docs.append(Document(source.id, source.tier, "advisory" if source.tier == "government" else "article",
                             url, canonical, _plain(entry.get("title", url)), text,
                             published.isoformat(timespec="seconds") if published else None,
                             {"feed_signature": signature, "feed_url": source.url, "text_source": text_source,
                              "author": entry.get("author"), "tags": [t.get("term", "") for t in entry.get("tags", [])]}))
    return len(feed.entries), docs, errors


def _kev(client: httpx.Client, source: SourceConfig, ctx: Context) -> tuple[int, list[Document]]:
    response = client.get(source.url)
    response.raise_for_status()
    entries = response.json()["vulnerabilities"]
    cutoff = (datetime.now(UTC) - timedelta(days=ctx.settings.kev_lookback_days)).date()
    docs = []
    for entry in entries:
        published = _date(entry.get("dateAdded"))
        if not published or datetime.fromisoformat(published).date() < cutoff:
            continue
        cve = entry["cveID"]
        text = "\n".join(f"{key}: {value}" for key, value in entry.items())
        docs.append(Document(source.id, source.tier, "vulnerability", f"https://nvd.nist.gov/vuln/detail/{cve}",
                             f"urn:cisa-kev:{cve}", f"{cve}: {entry['vulnerabilityName']}", text, published, entry))
    return len(entries), docs


def _threatfox(client: httpx.Client, source: SourceConfig, auth: str) -> tuple[int, list[Document]]:
    response = client.post(source.url, headers={"Auth-Key": auth}, json={"query": "get_iocs", "days": 1})
    response.raise_for_status()
    data = response.json()
    if data.get("query_status") == "no_result":
        return 0, []
    if data.get("query_status") != "ok":
        raise ValueError(f"ThreatFox query status: {data.get('query_status')}")
    groups: dict[tuple[str, str], list[dict]] = {}
    for entry in data["data"]:
        published = _date(entry.get("first_seen"))
        if not published:
            raise ValueError(f"invalid ThreatFox first_seen: {entry.get('first_seen')}")
        malware = entry.get("malware_printable") or entry.get("malware") or "unknown"
        item = {key: entry.get(key) for key in ("ioc_type", "ioc", "threat_type", "confidence_level", "tags", "reference", "first_seen")}
        item["malware"] = malware
        groups.setdefault((malware, published[:10]), []).append(item)
    docs = []
    for (malware, day), entries in sorted(groups.items()):
        slug = re.sub(r"[^a-z0-9]+", "-", malware.lower()).strip("-") or "unknown"
        entries.sort(key=lambda i: (i["ioc_type"], i["ioc"]))
        docs.append(Document(source.id, source.tier, "ioc_batch", source.url, f"urn:threatfox:{slug}:{day}",
                             f"ThreatFox: {malware} IOCs {day}", _threatfox_text(malware, entries), _date(day),
                             {"malware": malware, "iocs": entries}))
    return len(data["data"]), docs


def run(ctx: Context) -> dict:
    sources = [source for source in ctx.sources if source.enabled]
    known = {row["canonical_url"]: json.loads(row["meta_json"]).get("feed_signature")
             for row in ctx.db.execute("SELECT canonical_url, meta_json FROM documents")}
    existing_sources = {row[0] for row in ctx.db.execute("SELECT DISTINCT source_id FROM documents")}
    stats = {"sources_ok": 0, "sources_error": 0, "sources_skipped": 0, "items_seen": 0, "items_new": 0, "items_updated": 0}
    successful_sources = 0

    def fetch(source):
        if source.kind == "threatfox" and not os.environ.get("THREATFOX_AUTH_KEY"):
            return "skipped", 0, [], "THREATFOX_AUTH_KEY is not configured; authenticated ThreatFox collection skipped"
        with httpx.Client(headers={"User-Agent": ctx.settings.user_agent}, timeout=ctx.settings.http_timeout_seconds, follow_redirects=True) as client:
            errors = []
            if source.kind == "rss":
                seen, docs, errors = _rss(client, source, source.id not in existing_sources, known, ctx)
            elif source.kind == "cisa_kev":
                seen, docs = _kev(client, source, ctx)
            else:
                seen, docs = _threatfox(client, source, os.environ["THREATFOX_AUTH_KEY"])
        return ("error" if errors else "ok"), seen, docs, "; ".join(errors) if errors else None

    with ThreadPoolExecutor(max_workers=min(6, max(1, len(sources)))) as pool:
        pending = {pool.submit(fetch, source): source for source in sources}
        for future in as_completed(pending):
            source = pending[future]
            seen = new = updated = succeeded = 0
            try:
                status, seen, docs, error = future.result()
                for doc in docs:
                    _, change = _store(ctx, doc)
                    new += change == "new"
                    updated += change == "updated"
                    succeeded += 1
            except Exception as exc:
                ctx.db.rollback()
                status, error, new, updated = "error", f"{type(exc).__name__}: {exc}", 0, 0
                succeeded = 0
                ctx.log.warning("source %s failed: %s", source.id, error)
            ctx.db.execute("""INSERT INTO source_fetches (run_id, source_id, fetched_at, status, items_seen, items_new, items_updated, error)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                           (ctx.run_id, source.id, now_iso(), status, seen, new, updated, error))
            ctx.db.commit()
            stats[f"sources_{status}"] += 1
            successful_sources += status == "ok" or succeeded > 0
            stats["items_seen"] += seen
            stats["items_new"] += new
            stats["items_updated"] += updated
            ctx.log.info("source %s: %s seen=%d new=%d updated=%d", source.id, status, seen, new, updated)
    stats["status"] = ("partial" if successful_sources else "error") if stats["sources_error"] else "ok"
    return stats


def submit_url(ctx: Context, url: str) -> int:
    if urlsplit(url).scheme.lower() not in {"http", "https"}:
        raise ValueError("manual submissions require an HTTP or HTTPS URL")
    with httpx.Client(headers={"User-Agent": ctx.settings.user_agent}, timeout=ctx.settings.http_timeout_seconds, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        text = trafilatura.extract(response.text, url=url, include_tables=True, include_comments=False)
        if not text or not text.strip():
            raise ValueError("article contains no extractable main text")
        metadata = trafilatura.extract_metadata(response.text, default_url=url)
    doc = Document("manual", "manual", "article", url, canonicalize_url(url), metadata.title or url, text.strip(),
                   _date(metadata.date), {"text_source": "article"})
    document_id, _ = _store(ctx, doc)
    ctx.db.commit()
    return document_id
