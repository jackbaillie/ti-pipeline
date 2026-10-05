"""Self-contained analyst dashboard: relative links, local assets, escaped HTML."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tipipeline.pipeline import STAGES
from tipipeline.report import write_tree
from tipipeline.report.data import PRIORITY_ORDER, canonical_tactic, snapshot_from_context, tactic_sort_key
from tipipeline.report.markdown import kev_fields
from tipipeline.report.text import (
    CONTEXT_LABELS, INDICATOR_LABELS, PYRAMID_LABELS, defang_text, first_sentence,
    format_time, safe_url, truncate,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _technique_groups(s):
    groups = defaultdict(dict)
    invalid = []
    for use in s.technique_uses:
        if use.document_id not in s.docs:
            continue
        if not use.valid:
            invalid.append(use)
            continue
        known = s.attack.get(use.technique_id) if s.attack else None
        tactics = [canonical_tactic(t) for t in known.tactics] if known and known.tactics else [use.tactic]
        for tactic in tactics:
            entry = groups[tactic].setdefault(use.technique_id, {"id": use.technique_id, "name": use.name, "uses": [], "doc_ids": set(), "stated": 0, "inferred": 0, "explicit": 0, "verified": 0})
            entry["uses"].append(use)
            entry["doc_ids"].add(use.document_id)
            entry["stated"] += int(use.source == "llm" and use.basis == "stated")
            entry["inferred"] += int(use.source == "llm" and use.basis == "inferred")
            entry["explicit"] += int(use.source == "explicit")
            entry["verified"] += int(use.source == "llm" and use.verified)
    return [(tactic, sorted(entries.values(), key=lambda e: e["id"])) for tactic, entries in sorted(groups.items(), key=lambda pair: tactic_sort_key(pair[0]))], invalid


def generate(ctx, *, now: datetime | None = None) -> dict:
    s = snapshot_from_context(ctx, now or datetime.now(UTC))
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=select_autoescape(["html", "xml"], default=True), trim_blocks=True, lstrip_blocks=True)
    env.filters.update(
        timestamp=lambda value: format_time(value, s.tz),
        safe_url=safe_url,
        first_sentence=first_sentence,
        excerpt=truncate,
        defang_text=defang_text,
    )
    latest_fetches = {}
    for fetch in s.fetches:
        latest_fetches.setdefault(fetch.source_id, fetch)
    for source_id in s.sources:
        latest_fetches.setdefault(source_id, None)
    high_items = [r for rows in s.relevance_by_doc.values() for r in rows if r.priority == "high" and r.document_id in s.docs and s.docs[r.document_id].duplicate_of is None]
    high_items.sort(key=lambda r: (r.created_at, r.score), reverse=True)
    groups, invalid = _technique_groups(s)
    common = dict(s=s, stages=STAGES, priorities=PRIORITY_ORDER, indicator_labels=INDICATOR_LABELS, context_labels=CONTEXT_LABELS, pyramid_labels=PYRAMID_LABELS,
                  generated=s.generated_at.isoformat(), latest_fetches=latest_fetches, kev_fields=kev_fields)
    files = {}

    def render(path, template, *, base="", active="", **data):
        files[path] = env.get_template(template).render(**common, base=base, active=active, **data)

    render("index.html", "index.html", active="overview", high_items=high_items[:30], recent_docs=sorted(s.docs.values(), key=lambda d: (d.collected_at, d.id), reverse=True)[:50])
    for profile in ctx.profiles:
        rows = s.relevance_for_profile(profile.id)
        hunts = s.hunts_for_profile(profile.id)
        gaps = defaultdict(list)
        required = set()
        for h in hunts:
            if h.package:
                required.update(h.package.prepare.required_tables)
                for table in h.missing_tables:
                    gaps[table].append(h)
        render(f"profiles/{profile.id}.html", "profile.html", base="../", active=profile.id, profile=profile,
               relevance_groups=[(p, [r for r in rows if r.priority == p]) for p in PRIORITY_ORDER], hunts=hunts,
               kev=s.kev_matches(profile.id), required_tables=sorted(required), telemetry_gaps=dict(sorted(gaps.items())))
    for doc in s.docs.values():
        render(f"documents/{doc.id}.html", "document.html", base="../", doc=doc, analysis=s.analyses.get(doc.id),
               steps=s.steps(doc.id), explicit=s.explicit_techniques(doc.id), indicators=s.indicators_by_doc.get(doc.id, []),
               relevance=s.relevance_by_doc.get(doc.id, []), hunts=s.hunts_for_doc(doc.id), related=s.related(doc.id))
    for h in s.hunts.values():
        profile = s.profiles.get(h.profile_id)
        questions = {p.id: p.question for p in profile.pirs} if profile else {}
        render(f"hunts/{h.id}.html", "hunt.html", base="../", hunt=h, profile=profile, questions=questions)
    render("iocs.html", "iocs.html", active="iocs", indicators=s.indicators)
    render("attack.html", "attack.html", active="attack", technique_groups=groups, invalid=invalid)
    render("sources.html", "sources.html", active="sources", fetches=s.fetches)
    for asset in ("style.css", "app.js"):
        files[asset] = (TEMPLATE_DIR / asset).read_text(encoding="utf-8")
    write_tree(ctx.output_dir / "dashboard", files, suffixes=(".html", ".css", ".js"))
    ctx.log.info("Rendered dashboard: %d documents, %d hunts, %d profiles", len(s.docs), len(s.hunts), len(s.profiles))
    return {"pages": len(files)-2, "documents": len(s.docs), "hunts": len(s.hunts), "profiles": len(s.profiles)}


def run(ctx) -> dict:
    return generate(ctx)
