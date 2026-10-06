"""Static analyst dashboard.

Every page is plain HTML with relative links, one local stylesheet and one local
script, so the folder works from disk or behind any static file server. Jinja
autoescapes all report text. Counts, groupings and sort orders are prepared here;
the templates only lay the data out.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tipipeline.models import Profile, SourceConfig, Theme
from tipipeline.pipeline import STAGES
from tipipeline.report import write_tree
from tipipeline.report.data import (
    PRIORITY_RANK,
    Doc,
    Fetch,
    Hunt,
    Impact,
    Snapshot,
    Story,
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
    parse_iso,
    safe_url,
    truncate,
)

TEMPLATE_DIR = Path(__file__).parent / "templates"

# The overview counts what was published (or, without a date, collected) in this window.
PERIOD_DAYS = 14
# Technique trends look further back: a month of reporting gives steadier counts.
TRENDING_DAYS = 30
OVERVIEW_STORY_LIMIT = 8
OVERVIEW_HUNT_LIMIT = 5
OVERVIEW_TECHNIQUE_LIMIT = 6
ATTACK_TRENDING_LIMIT = 10
RECENT_DOCUMENT_LIMIT = 50
# Product and CVE chips shown per story before "+N".
TAG_LIMIT = 4
HEAT_LEVELS = 4
# IOC and CVE tables show this many rows until "Show all" is pressed.
INITIAL_ROWS = 100
# Matches deploy/systemd/ti-pipeline.timer.
RUN_ZONE = ZoneInfo("Europe/London")
RUN_HOURS = (8, 20)
CUSTOMER_ORDER = ("law-firm", "retail-bank", "manufacturer-ot")

# Status values grouped into the four chip colours in style.css.
STATUS_TONES = {
    "ok": "ok",
    "prepared": "ok",
    "verified": "ok",
    "completed": "ok",
    "done": "ok",
    "partial": "warn",
    "running": "warn",
    "unverified": "warn",
    "error": "bad",
    "failed": "bad",
}

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


@dataclass
class Tile:
    label: str
    value: int
    note: str
    href: str


@dataclass
class StoryRow:
    story: Story
    shown: Impact | None  # the assessment in the score box and the reason line
    tags: list[tuple[str, bool]]  # (label, is_cve)
    more_tags: int
    hunts: list[Hunt]
    match: str  # filter tokens, see _match
    search: str  # includes titles, products and CVEs even when their visible labels are truncated


@dataclass
class HuntRow:
    hunt: Hunt
    trigger: Doc | None
    themes: list[Theme]
    match: str


@dataclass
class HuntGroup:
    theme: Theme | None  # None collects hunts with no themed PIR
    rows: list[HuntRow]


@dataclass
class CustomerSummary:
    profile: Profile
    high: int
    medium: int
    top_theme: Theme | None


@dataclass
class HeatCell:
    profile: Profile
    count: int
    level: int
    href: str


@dataclass
class HeatRow:
    theme: Theme
    cells: list[HeatCell]


@dataclass
class TechniqueRow:
    id: str
    name: str
    tactic: str
    docs: list[Doc]  # newest first
    customers: list[str]  # profile ids with a medium or high story that includes the technique
    hunts: list[Hunt]
    anchor: bool = False  # first appearance in the tree carries the #id

    @property
    def url(self) -> str:
        return ATTACK_URL.format(self.id.replace(".", "/"))


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


def next_run(after: datetime) -> datetime:
    """The first scheduled run strictly after ``after``."""
    local = after.astimezone(RUN_ZONE)
    slots = (
        datetime.combine(local.date() + timedelta(days=day), time(hour), tzinfo=RUN_ZONE)
        for day in (0, 1)
        for hour in RUN_HOURS
    )
    return next(slot for slot in slots if slot > local)


def flag_label(reason: str) -> str:
    """Why an indicator is treated as benign (document_indicators.warninglist)."""
    if reason == "allowlist":
        return "Allowlist"
    if reason == "publisher":
        return "Publisher's own domain"
    return f"MISP list: {reason}"


def _after(value: str | None, since: datetime) -> bool:
    parsed = parse_iso(value)
    return parsed is not None and parsed >= since


def _match(entries: list[tuple[str, str, list[Theme]]]) -> str:
    """Filter tokens ``customer|priority-rank|theme`` read by app.js; ``-`` means no theme."""
    tokens = []
    for profile_id, priority, themes in entries:
        rank = PRIORITY_RANK.get(priority, len(PRIORITY_RANK))
        tokens += [f"{profile_id}|{rank}|{theme_id}" for theme_id in ([t.id for t in themes] or ["-"])]
    return " ".join(tokens)


def _story_row(story: Story, profile_id: str | None = None) -> StoryRow:
    shown = story.impact(profile_id) if profile_id else story.best
    tags = [(label, False) for label in story.products] + [(cve, True) for cve in story.cves]
    return StoryRow(
        story=story,
        shown=shown,
        tags=tags[:TAG_LIMIT],
        more_tags=max(0, len(tags) - TAG_LIMIT),
        hunts=[h for h in story.hunts if profile_id in (None, h.profile_id)],
        match=_match([(i.profile_id, i.priority, i.themes) for i in story.impacts]),
        search=" ".join([
            *(d.title + " " + d.source_name for d in story.members),
            *story.products,
            *story.cves,
        ]),
    )


def _hunt_row(s: Snapshot, hunt: Hunt) -> HuntRow:
    themes = s.hunt_themes(hunt)
    return HuntRow(hunt, s.docs.get(hunt.document_id), themes, _match([(hunt.profile_id, hunt.priority or "none", themes)]))


def _hunt_groups(s: Snapshot, hunts) -> list[HuntGroup]:
    """Hunts under the theme of their first matched PIR, in theme order; unthemed hunts last."""
    grouped: dict[str | None, list[HuntRow]] = defaultdict(list)
    for hunt in hunts:
        row = _hunt_row(s, hunt)
        grouped[row.themes[0].id if row.themes else None].append(row)
    for rows in grouped.values():
        rows.sort(key=lambda r: (r.hunt.created_at, r.hunt.id), reverse=True)
        rows.sort(key=lambda r: PRIORITY_RANK.get(r.hunt.priority or "", len(PRIORITY_RANK)))
    groups = [HuntGroup(theme, grouped[theme.id]) for theme in s.themes.values() if theme.id in grouped]
    if None in grouped:
        groups.append(HuntGroup(None, grouped[None]))
    return groups


def _technique_rows(s: Snapshot, since: datetime | None = None) -> dict[str, TechniqueRow]:
    """Valid techniques seen in reporting (optionally since a date), keyed by ID."""
    hunts_by_technique: dict[str, list[Hunt]] = defaultdict(list)
    for hunt in sorted(s.hunts.values(), key=lambda h: (h.created_at, h.id), reverse=True):
        for technique_id in hunt.technique_ids:
            hunts_by_technique[technique_id].append(hunt)
    docs: dict[str, set[int]] = defaultdict(set)
    names: dict[str, str] = {}
    tactics: dict[str, str] = {}
    for use in s.technique_uses:
        doc = s.docs.get(use.document_id)
        if not use.valid or doc is None or (since and doc.when < since):
            continue
        docs[use.technique_id].add(doc.id)
        known = s.attack.get(use.technique_id) if s.attack else None
        names.setdefault(use.technique_id, use.name or (known.name if known else ""))
        tactics.setdefault(use.technique_id, canonical_tactic(known.tactics[0]) if known and known.tactics else use.tactic)
    order = list(s.profiles)
    rows = {}
    for technique_id, doc_ids in docs.items():
        customers = {
            impact.profile_id
            for doc_id in doc_ids
            for impact in (s.story_by_doc[doc_id].impacts if doc_id in s.story_by_doc else [])
            if impact.priority in ("high", "medium")
        }
        rows[technique_id] = TechniqueRow(
            id=technique_id,
            name=names[technique_id],
            tactic=tactics[technique_id],
            docs=sorted((s.docs[i] for i in doc_ids), key=lambda d: (d.when, d.id), reverse=True),
            customers=[p for p in order if p in customers],
            hunts=hunts_by_technique.get(technique_id, []),
        )
    return rows


def _trending(s: Snapshot, limit: int) -> list[TechniqueRow]:
    rows = _technique_rows(s, s.generated_at - timedelta(days=TRENDING_DAYS)).values()
    return sorted(rows, key=lambda r: (-len(r.docs), r.id))[:limit]


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
    since = s.generated_at - timedelta(days=PERIOD_DAYS)
    stories = [story for story in s.stories if story.latest >= since]
    reports = [d for d in s.docs.values() if d.when >= since and d.duplicate_of is None]
    hunts = [h for h in s.hunts.values() if _after(h.created_at, since)]
    iocs = [i for i in s.indicators if i.type != "cve" and i.status == "qualified" and _after(i.first_seen, since)]
    high = sum(any(i.priority == "high" for i in story.impacts) for story in stories)
    tiles = [
        Tile("New reports", len(reports), f"from {len({d.source_id for d in reports})} sources", "reports.html"),
        Tile("High-priority stories", high, f"of {len(stories)} stories", "reports.html?priority=high"),
        Tile("Hunts drafted", len(hunts), f"{sum(len(h.queries) for h in hunts)} KQL queries", "hunts.html"),
        Tile("New qualified IOCs", len(iocs), "from IOC sections and feeds", "iocs.html"),
    ]

    customers, heat_counts = [], {}
    for profile in s.profiles.values():
        impacts = [story.impact(profile.id) for story in stories]
        relevant = [i for i in impacts if i and i.priority in ("high", "medium")]
        themes = Counter(theme.id for impact in relevant for theme in impact.themes)
        top = max(s.themes.values(), key=lambda t: themes[t.id], default=None) if themes else None
        customers.append(CustomerSummary(
            profile=profile,
            high=sum(i.priority == "high" for i in relevant),
            medium=sum(i.priority == "medium" for i in relevant),
            top_theme=top,
        ))
        heat_counts[profile.id] = themes
    peak = max((n for counts in heat_counts.values() for n in counts.values()), default=0)
    heat = [
        HeatRow(theme, [
            HeatCell(
                profile=profile,
                count=heat_counts[profile.id][theme.id],
                level=math.ceil(HEAT_LEVELS * heat_counts[profile.id][theme.id] / peak) if peak else 0,
                href=f"reports.html?customer={profile.id}&theme={theme.id}&priority=medium",
            )
            for profile in s.profiles.values()
        ])
        for theme in s.themes.values()
    ]

    latest_hunts = sorted(s.hunts.values(), key=lambda h: (h.created_at, h.id), reverse=True)[:OVERVIEW_HUNT_LIMIT]
    return dict(
        period_days=PERIOD_DAYS,
        period_start=since,
        tiles=tiles,
        key_stories=[_story_row(story) for story in stories if story.impacts][:OVERVIEW_STORY_LIMIT],
        customers=customers,
        heat=heat,
        trending=_trending(s, OVERVIEW_TECHNIQUE_LIMIT),
        trending_days=TRENDING_DAYS,
        latest_hunts=[_hunt_row(s, h) for h in latest_hunts],
        hunt_total=len(s.hunts),
    )


def _reports_page(s: Snapshot) -> dict:
    return dict(stories=[_story_row(story) for story in s.stories])


def _hunts_page(s: Snapshot) -> dict:
    return dict(groups=_hunt_groups(s, s.hunts.values()), total=len(s.hunts))


def _profile_page(s: Snapshot, profile: Profile) -> dict:
    assessed = [story for story in s.stories if story.impact(profile.id)]
    assessed.sort(key=lambda story: (story.impact(profile.id).score, story.latest), reverse=True)
    rows = [_story_row(story, profile.id) for story in assessed]
    pir_groups = [(theme, [p for p in profile.pirs if p.theme == theme.id]) for theme in s.themes.values()]
    hunts = [h for h in s.hunts.values() if h.profile_id == profile.id]
    return dict(
        profile=profile,
        pir_groups=[(theme, pirs) for theme, pirs in pir_groups if pirs],
        key_stories=[row for row in rows if row.shown.priority in ("high", "medium")],
        low_stories=[row for row in rows if row.shown.priority == "low"],
        hunt_groups=_hunt_groups(s, hunts),
        hunt_count=len(hunts),
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
    order = {profile_id: index for index, profile_id in enumerate(s.profiles)}
    relevance = sorted(
        (r for r in s.relevance_by_doc.get(doc.id, []) if r.profile_id in s.profiles),
        key=lambda r: order[r.profile_id],
    )
    found = s.indicators_by_doc.get(doc.id, [])
    # CVEs are vulnerabilities, not IOCs; qualified IOCs first.
    indicators = sorted((i for i in found if i.type != "cve"), key=lambda i: (i.status != "qualified", i.type, i.value))
    story = s.story_by_doc.get(doc.id)
    return dict(
        doc=doc,
        analysis=analysis,
        technologies=technologies,
        steps=s.steps(doc.id),
        relevance=[(r, s.pir_themes(r.profile_id, r.matched_pirs)) for r in relevance],
        indicators=indicators,
        indicator_counts=Counter(i.status for i in indicators),
        cves=sorted({i.value for i in found if i.type == "cve"}),
        story=story,
        related=[d for d in story.members if d.id != doc.id] if story else [],
        hunts=[_hunt_row(s, h) for h in (story.hunts if story else s.hunts_for_doc(doc.id))],
        has_brief=doc.id in briefs,
    )


def _hunt_page(s: Snapshot, hunt: Hunt) -> dict:
    profile = s.profiles.get(hunt.profile_id)
    doc = s.docs.get(hunt.document_id)
    act_lists, evidence, show_act = [], [], False
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
        show_act = bool(act_lists) or act.outcome != "pending"
        evidence = [e for e in hunt.package.prepare.evidence if e.verified]
    pirs = {pir.id: pir for pir in profile.pirs} if profile else {}
    matched = hunt.package.prepare.matched_pirs if hunt.package else []
    return dict(
        hunt=hunt,
        profile=profile,
        doc=doc,
        themes=s.hunt_themes(hunt),
        matched_pirs=[pirs[p] for p in matched if p in pirs],
        # Behavioural queries test the hypothesis; IOC sweeps follow.
        queries=sorted(hunt.queries, key=lambda q: (q.kind == "ioc_sweep", q.id)),
        evidence=evidence,
        act_lists=act_lists,
        show_act=show_act,
        current_version=doc.version if doc and doc.version != hunt.document_version else None,
    )


def _attack_page(s: Snapshot) -> dict:
    rows = _technique_rows(s)
    groups: dict[str, list[TechniqueRow]] = defaultdict(list)
    for row in sorted(rows.values(), key=lambda r: r.id):
        known = s.attack.get(row.id) if s.attack else None
        tactics = {canonical_tactic(t) for t in known.tactics} if known and known.tactics else {row.tactic}
        for index, tactic in enumerate(sorted(tactics, key=tactic_sort_key)):
            groups[tactic].append(replace(row, anchor=index == 0))
    return dict(
        trending=_trending(s, ATTACK_TRENDING_LIMIT),
        trending_days=TRENDING_DAYS,
        tactics=sorted(groups.items(), key=lambda pair: tactic_sort_key(pair[0])),
    )


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


def _ordered_profiles(profiles: list[Profile]) -> list[Profile]:
    order = {profile_id: index for index, profile_id in enumerate(CUSTOMER_ORDER)}
    return sorted(profiles, key=lambda p: order.get(p.id, len(order)))


def _nav(profiles: list[Profile]) -> list[tuple[str, list[tuple[str, str, str]]]]:
    """Sidebar groups of (href, label, active key)."""
    return [
        ("Intelligence", [
            ("index.html", "Overview", "overview"),
            ("reports.html", "Reports", "reports"),
            ("hunts.html", "Hunts", "hunts"),
            ("investigate.html", "Investigate", "investigate"),
        ]),
        ("Customers", [(f"profiles/{p.id}.html", p.short_name, p.id) for p in profiles]),
        ("Reference", [("iocs.html", "IOCs", "iocs"), ("cves.html", "CVEs", "cves"), ("attack.html", "ATT&CK", "attack")]),
        ("System", [("pipeline.html", "Pipeline", "pipeline")]),
    ]


def _day(value: str | datetime | None, tz: ZoneInfo, now: datetime) -> str:
    """Short date such as ``5 Oct``; the year is added outside the current one."""
    parsed = value if isinstance(value, datetime) else parse_iso(value)
    if parsed is None:
        return value or "—"
    local = parsed.astimezone(tz)
    return f"{local.day} {local:%b}" + ("" if local.year == now.astimezone(tz).year else f" {local.year}")


def page_shell(ctx, now: datetime | None = None) -> tuple[Environment, dict]:
    """Jinja environment and the variables every page needs (navigation, run status).

    The live investigation pages use this too, so it reads only the context and
    the latest finished run, never a full snapshot.
    """
    now = now or datetime.now(UTC)
    tz = ZoneInfo(ctx.settings.timezone)
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    customers = {p.id: p.short_name for p in ctx.profiles}
    env.filters.update(
        timestamp=lambda value: format_time(value, tz),
        day=lambda value: _day(value, tz, now),
        customer=lambda profile_id: customers.get(profile_id, profile_id),
        tone=lambda status: STATUS_TONES.get(status, "neutral"),
        label=lambda value: str(value).replace("_", " "),
        thousands=lambda n: f"{n:,}",
        truncate_text=truncate,
        flag_label=flag_label,
        safe_url=safe_url,
        first_sentence=first_sentence,
        defang_text=defang_text,
    )
    last = ctx.db.execute(
        "SELECT status FROM runs WHERE finished_at IS NOT NULL ORDER BY started_at DESC, id DESC LIMIT 1"
    ).fetchone()
    upcoming = next_run(now).astimezone(tz)
    current = now.astimezone(tz)
    common = dict(
        nav=_nav(_ordered_profiles(ctx.profiles)),
        updated_label=f"{_day(current, tz, now)}, {current:%H:%M}",
        next_run_label=f"{_day(upcoming, tz, now)}, {upcoming:%H:%M}",
        run_status=last["status"] if last else None,
        source_names={source.id: source.name for source in ctx.sources},
        indicator_labels=INDICATOR_LABELS,
        context_labels=CONTEXT_LABELS,
        pyramid_labels=PYRAMID_LABELS,
        kev_fields=kev_fields,
        initial_rows=INITIAL_ROWS,
    )
    return env, common


def generate(ctx, *, now: datetime | None = None) -> dict:
    # Imported here: the investigation pages import page_shell from this module.
    from tipipeline.dashboard.investigations import render_pages

    s = snapshot_from_context(ctx, now or datetime.now(UTC))
    s.profiles = {p.id: p for p in _ordered_profiles(ctx.profiles)}
    env, common = page_shell(ctx, s.generated_at)
    env.filters["docs"] = lambda ids: [s.docs[i] for i in ids if i in s.docs]
    files: dict[str, str] = {}

    def render(path: str, template: str, *, base: str = "", active: str = "", **data) -> None:
        files[path] = env.get_template(template).render(**common, s=s, base=base, active=active, **data)

    render("index.html", "index.html", active="overview", **_overview(s))
    render("reports.html", "reports.html", active="reports", **_reports_page(s))
    render("hunts.html", "hunts.html", active="hunts", **_hunts_page(s))
    for profile in s.profiles.values():
        render(f"profiles/{profile.id}.html", "profile.html", base="../", active=profile.id, **_profile_page(s, profile))
    briefs = set(s.assessed_doc_ids())
    for doc in s.docs.values():
        render(f"documents/{doc.id}.html", "document.html", base="../", active="reports", **_document_page(s, doc, briefs))
    for hunt in s.hunts.values():
        render(f"hunts/{hunt.id}.html", "hunt.html", base="../", active="hunts", **_hunt_page(s, hunt))

    iocs = [i for i in s.indicators if i.type != "cve"]
    cves = [i for i in s.indicators if i.type == "cve"]
    kev_docs = {d.meta["cveID"]: d for d in s.docs.values() if d.is_kev and d.meta.get("cveID")}
    render("iocs.html", "iocs.html", active="iocs", indicators=iocs, ioc_counts=Counter(i.status for i in iocs))
    render("cves.html", "cves.html", active="cves", cves=cves, kev_docs=kev_docs)
    render("attack.html", "attack.html", active="attack", **_attack_page(s))
    render("pipeline.html", "pipeline.html", active="pipeline", **_pipeline_page(s))
    files.update(render_pages(ctx, env, common))

    for asset in ("style.css", "app.js"):
        files[asset] = (TEMPLATE_DIR / asset).read_text(encoding="utf-8")
    write_tree(ctx.output_dir / "dashboard", files, suffixes=(".html", ".css", ".js"))
    ctx.log.info("Rendered dashboard: %d documents, %d hunts, %d profiles", len(s.docs), len(s.hunts), len(s.profiles))
    return {"pages": len(files) - 2, "documents": len(s.docs), "hunts": len(s.hunts), "profiles": len(s.profiles)}


def run(ctx) -> dict:
    return generate(ctx)
