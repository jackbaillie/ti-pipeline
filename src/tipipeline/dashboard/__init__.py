"""Static analyst dashboard.

Every page is plain HTML with relative links, one local stylesheet and one local
script, so the folder works from disk or behind any static file server. Jinja
autoescapes all report text. Counts, groupings and sort orders are prepared here;
the templates only lay the data out.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tipipeline.models import Profile, SourceConfig
from tipipeline.pipeline import STAGES
from tipipeline.report import write_tree
from tipipeline.report.data import (
    PRIORITY_ORDER,
    PRIORITY_RANK,
    Doc,
    Fetch,
    Hunt,
    Relevance,
    Snapshot,
    canonical_tactic,
    snapshot_from_context,
    tactic_sort_key,
)
from tipipeline.report.markdown import kev_fields
from tipipeline.report.text import (
    CONTEXT_LABELS,
    INDICATOR_LABELS,
    PYRAMID_LABELS,
    defang_text,
    first_sentence,
    format_time,
    safe_url,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"

OVERVIEW_HUNT_LIMIT = 10
OVERVIEW_HIGH_LIMIT = 10
RECENT_DOCUMENT_LIMIT = 50
# IOC and CVE tables show this many rows until "Show all" is pressed.
# Without JavaScript every row is visible.
INITIAL_ROWS = 100

# Status values grouped into the four chip colours in style.css.
STATUS_TONES = {
    "ok": "ok",
    "prepared": "ok",
    "schema_valid": "ok",
    "verified": "ok",
    "completed": "ok",
    "warnings": "warn",
    "partial": "warn",
    "insufficient_telemetry": "warn",
    "unverified": "warn",
    "invalid": "bad",
    "error": "bad",
    "failed": "bad",
}


@dataclass
class HuntRow:
    hunt: Hunt
    priority: str | None
    trigger: Doc | None
    query_issues: dict[str, int]  # validation status -> count, for queries that are not schema_valid


@dataclass
class RelevanceRow:
    relevance: Relevance
    doc: Doc
    hunt: Hunt | None


@dataclass
class CustomerCard:
    profile: Profile
    high: int
    medium: int
    hunts_ready: int
    missing_tables: int


@dataclass
class SourceHealth:
    id: str
    config: SourceConfig | None
    fetch: Fetch | None


@dataclass
class StageRow:
    name: str
    status: str
    seconds: float | None
    note: str


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _hunt_row(s: Snapshot, hunt: Hunt) -> HuntRow:
    issues = Counter(q.validation_status for q in hunt.queries if q.validation_status != "schema_valid")
    return HuntRow(
        hunt=hunt,
        priority=hunt.package.prepare.priority if hunt.package else None,
        trigger=s.docs.get(hunt.document_id),
        query_issues=dict(sorted(issues.items())),
    )


def _priority_then_newest(rows) -> list[HuntRow]:
    rows = sorted(rows, key=lambda r: (r.hunt.updated_at, r.hunt.id), reverse=True)
    return sorted(rows, key=lambda r: PRIORITY_RANK.get(r.priority, len(PRIORITY_ORDER)))


def _missing_tables(hunts: list[Hunt]) -> dict[str, list[Hunt]]:
    """Table name -> hunts that need it but the customer does not collect it."""
    gaps: dict[str, list[Hunt]] = defaultdict(list)
    for hunt in hunts:
        for table in hunt.missing_tables:
            gaps[table].append(hunt)
    return dict(sorted(gaps.items()))


def _relevance_rows(s: Snapshot, assessments: list[Relevance]) -> list[RelevanceRow]:
    return [
        RelevanceRow(r, s.docs[r.document_id], s.hunt_for(r.document_id, r.profile_id))
        for r in assessments
        if r.document_id in s.docs
    ]


def _stage_note(result: dict) -> str:
    """Error or skip reason, then the stage's own integer counters (e.g. "items new 5")."""
    if not result:
        return "Not recorded"
    counters = [
        f"{key.replace('_', ' ')} {value:,}"
        for key, value in result.items()
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    return " · ".join(part for part in [result.get("error") or result.get("reason"), *counters] if part)


# --------------------------------------------------------------------------
# Page views
# --------------------------------------------------------------------------


def _overview(s: Snapshot) -> dict:
    ready = _priority_then_newest(_hunt_row(s, h) for h in s.hunts.values() if h.status == "prepared")

    high = [r for rows in s.relevance_by_doc.values() for r in rows if r.priority == "high"]
    high_rows = [row for row in _relevance_rows(s, high) if row.doc.duplicate_of is None]
    high_rows.sort(key=lambda row: (row.relevance.created_at, row.relevance.score), reverse=True)

    customers = []
    for profile in s.profiles.values():
        priorities = Counter(r.priority for r in s.relevance_for_profile(profile.id))
        hunts = s.hunts_for_profile(profile.id)
        customers.append(
            CustomerCard(
                profile=profile,
                high=priorities["high"],
                medium=priorities["medium"],
                hunts_ready=sum(h.status == "prepared" for h in hunts),
                missing_tables=len(_missing_tables(hunts)),
            )
        )

    facts = [
        (len(s.docs), "documents", None),
        (sum(a.status == "ok" for a in s.analyses.values()), "analysed", None),
        (sum(i.type != "cve" for i in s.indicators), "IOCs", "iocs.html"),
        (sum(i.type == "cve" for i in s.indicators), "CVEs", "cves.html"),
        (len(s.hunts), "hunts", None),
    ]
    return dict(
        latest_run=s.latest_run(),
        facts=facts,
        customers=customers,
        ready_hunts=ready[:OVERVIEW_HUNT_LIMIT],
        ready_total=len(ready),
        high_items=high_rows[:OVERVIEW_HIGH_LIMIT],
        high_total=len(high_rows),
    )


def _profile_page(s: Snapshot, profile: Profile) -> dict:
    hunts = s.hunts_for_profile(profile.id)
    rows = _relevance_rows(s, s.relevance_for_profile(profile.id))
    return dict(
        profile=profile,
        hunts=_priority_then_newest(_hunt_row(s, h) for h in hunts),
        relevance={level: [row for row in rows if row.relevance.priority == level] for level in PRIORITY_ORDER},
        kev=s.kev_matches(profile.id),
        required_tables={t for h in hunts if h.package for t in h.package.prepare.required_tables},
        telemetry_gaps=_missing_tables(hunts),
    )


def _document_page(s: Snapshot, doc: Doc, briefs: set[int]) -> dict:
    analysis = s.analyses.get(doc.id)
    technologies = []
    if analysis and analysis.report:
        checks = analysis.validation.technology_quotes_verified if analysis.validation else []
        technologies = [
            (tech, index < len(checks) and checks[index])
            for index, tech in enumerate(analysis.report.affected_technologies)
        ]
    return dict(
        doc=doc,
        analysis=analysis,
        technologies=technologies,
        steps=s.steps(doc.id),
        explicit=s.explicit_techniques(doc.id),
        indicators=s.indicators_by_doc.get(doc.id, []),
        relevance=s.relevance_by_doc.get(doc.id, []),
        hunts=s.hunts_for_doc(doc.id),
        related=s.related(doc.id),
        has_brief=doc.id in briefs,
    )


def _hunt_page(s: Snapshot, hunt: Hunt) -> dict:
    profile = s.profiles.get(hunt.profile_id)
    doc = s.docs.get(hunt.document_id)
    act_lists = []
    if hunt.package:
        act = hunt.package.act
        candidates = [
            ("Findings", act.findings),
            ("Gaps", act.gaps),
            ("Recommendations", act.recommendations),
            ("Detection proposals", act.detections_proposed),
            ("Future hunts", act.future_hunts),
        ]
        act_lists = [(label, values) for label, values in candidates if values]
    return dict(
        hunt=hunt,
        profile=profile,
        questions={pir.id: pir.question for pir in profile.pirs} if profile else {},
        current_version=doc.version if doc and doc.version != hunt.document_version else None,
        act_lists=act_lists,
    )


def _technique_groups(s: Snapshot) -> tuple[list[tuple[str, list[dict]]], list]:
    """Valid technique uses grouped by official tactic, plus the invalid IDs."""
    groups: dict[str, dict[str, dict]] = defaultdict(dict)
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
            entry = groups[tactic].setdefault(
                use.technique_id,
                {"id": use.technique_id, "name": use.name, "uses": [], "doc_ids": set(),
                 "stated": 0, "inferred": 0, "explicit": 0, "verified": 0},
            )
            entry["uses"].append(use)
            entry["doc_ids"].add(use.document_id)
            entry["stated"] += int(use.source == "llm" and use.basis == "stated")
            entry["inferred"] += int(use.source == "llm" and use.basis == "inferred")
            entry["explicit"] += int(use.source == "explicit")
            entry["verified"] += int(use.source == "llm" and use.verified)
    ordered = sorted(groups.items(), key=lambda pair: tactic_sort_key(pair[0]))
    return [(tactic, sorted(entries.values(), key=lambda e: e["id"])) for tactic, entries in ordered], invalid


def _pipeline_page(s: Snapshot) -> dict:
    latest = s.latest_run()
    stage_run = latest if latest and latest.stages else s.last_finished_run()
    stages = []
    if stage_run:
        for name in STAGES:
            result = stage_run.stages.get(name, {})
            stages.append(StageRow(name, result.get("status", "pending"), result.get("seconds"), _stage_note(result)))

    latest_fetch: dict[str, Fetch] = {}
    for fetch in s.fetches:  # newest first
        latest_fetch.setdefault(fetch.source_id, fetch)
    source_ids = list(s.sources) + [i for i in latest_fetch if i not in s.sources]

    return dict(
        latest_run=latest,
        stage_run=stage_run,
        stages=stages,
        sources=[SourceHealth(i, s.sources.get(i), latest_fetch.get(i)) for i in source_ids],
        fetches=s.fetches,
        recent_docs=sorted(s.docs.values(), key=lambda d: (d.collected_at, d.id), reverse=True)[:RECENT_DOCUMENT_LIMIT],
        recent_limit=RECENT_DOCUMENT_LIMIT,
    )


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _environment(s: Snapshot) -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    customers = {p.id: p.short_name for p in s.profiles.values()}
    env.filters.update(
        timestamp=lambda value: format_time(value, s.tz),
        customer=lambda profile_id: customers.get(profile_id, profile_id),
        tone=lambda status: STATUS_TONES.get(status, "neutral"),
        label=lambda value: str(value).replace("_", " "),
        thousands=lambda n: f"{n:,}",
        safe_url=safe_url,
        first_sentence=first_sentence,
        defang_text=defang_text,
    )
    return env


def generate(ctx, *, now: datetime | None = None) -> dict:
    s = snapshot_from_context(ctx, now or datetime.now(UTC))
    env = _environment(s)
    nav = [("index.html", "Overview", "overview")]
    nav += [(f"profiles/{p.id}.html", p.short_name, p.id) for p in s.profiles.values()]
    nav += [("iocs.html", "IOCs", "iocs"), ("attack.html", "ATT&CK", "attack"), ("pipeline.html", "Pipeline", "pipeline")]
    common = dict(
        s=s,
        nav=nav,
        snapshot_label=format_time(s.generated_at.isoformat(), s.tz, with_zone=True),
        source_names={source_id: source.name for source_id, source in s.sources.items()},
        indicator_labels=INDICATOR_LABELS,
        context_labels=CONTEXT_LABELS,
        pyramid_labels=PYRAMID_LABELS,
        kev_fields=kev_fields,
        initial_rows=INITIAL_ROWS,
    )
    files: dict[str, str] = {}

    def render(path: str, template: str, *, base: str = "", active: str = "", **data) -> None:
        files[path] = env.get_template(template).render(**common, base=base, active=active, **data)

    render("index.html", "index.html", active="overview", **_overview(s))
    for profile in s.profiles.values():
        render(f"profiles/{profile.id}.html", "profile.html", base="../", active=profile.id, **_profile_page(s, profile))
    briefs = set(s.assessed_doc_ids())
    for doc in s.docs.values():
        render(f"documents/{doc.id}.html", "document.html", base="../", **_document_page(s, doc, briefs))
    for hunt in s.hunts.values():
        render(f"hunts/{hunt.id}.html", "hunt.html", base="../", **_hunt_page(s, hunt))

    iocs = [i for i in s.indicators if i.type != "cve"]
    cves = [i for i in s.indicators if i.type == "cve"]
    kev_docs = {d.meta["cveID"]: d for d in s.docs.values() if d.is_kev and d.meta.get("cveID")}
    render("iocs.html", "iocs.html", active="iocs", indicators=iocs, cve_count=len(cves))
    render("cves.html", "cves.html", active="iocs", cves=cves, kev_docs=kev_docs)

    groups, invalid = _technique_groups(s)
    render("attack.html", "attack.html", active="attack", technique_groups=groups, invalid=invalid)
    render("pipeline.html", "pipeline.html", active="pipeline", **_pipeline_page(s))

    for asset in ("style.css", "app.js"):
        files[asset] = (TEMPLATE_DIR / asset).read_text(encoding="utf-8")
    write_tree(ctx.output_dir / "dashboard", files, suffixes=(".html", ".css", ".js"))
    ctx.log.info("Rendered dashboard: %d documents, %d hunts, %d profiles", len(s.docs), len(s.hunts), len(s.profiles))
    return {"pages": len(files) - 2, "documents": len(s.docs), "hunts": len(s.hunts), "profiles": len(s.profiles)}


def run(ctx) -> dict:
    return generate(ctx)
