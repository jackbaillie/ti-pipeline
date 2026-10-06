"""Read-only view of the database used by the report and dashboard stages.

All rows are loaded once into plain dataclasses so both renderers share the
same interpretation of the stored JSON (``ReportAnalysis``,
``AnalysisValidation``, ``HuntPackage``, ``KqlValidation``). Malformed JSON
never aborts rendering: the affected record is shown with a parse error.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import ValidationError

from tipipeline.attack import Attack
from tipipeline.models import (
    AnalysisValidation,
    HuntPackage,
    KqlValidation,
    Profile,
    ReportAnalysis,
    SourceConfig,
)
from tipipeline.report.text import defang, slugify

PRIORITY_ORDER = ("high", "medium", "low", "none")
PRIORITY_RANK = {name: rank for rank, name in enumerate(PRIORITY_ORDER)}

TACTIC_ORDER = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_LOOKUP = {name.lower(): name for name in TACTIC_ORDER}
_TACTIC_LOOKUP["defence evasion"] = "Defense Evasion"
UNMAPPED_TACTIC = "Tactic not stated"


def canonical_tactic(name: str | None) -> str:
    if not name or not name.strip():
        return UNMAPPED_TACTIC
    key = " ".join(name.replace("-", " ").replace("_", " ").split()).lower()
    return _TACTIC_LOOKUP.get(key, " ".join(name.split()))


def tactic_sort_key(name: str) -> tuple[int, str]:
    try:
        return (TACTIC_ORDER.index(name), name)
    except ValueError:
        return (len(TACTIC_ORDER) + (1 if name == UNMAPPED_TACTIC else 0), name)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


@dataclass
class Run:
    id: int
    started_at: str
    finished_at: str | None
    status: str
    stages: dict[str, dict]


@dataclass
class Fetch:
    id: int
    run_id: int | None
    source_id: str
    fetched_at: str
    status: str
    items_seen: int
    items_new: int
    items_updated: int
    error: str | None


@dataclass
class Doc:
    id: int
    source_id: str
    source_name: str
    kind: str
    tier: str
    url: str
    title: str
    published_at: str | None
    collected_at: str
    updated_at: str
    version: int
    meta: dict
    duplicate_of: int | None
    cluster_id: int | None

    @property
    def is_kev(self) -> bool:
        return self.kind == "vulnerability"


@dataclass
class Analysis:
    document_id: int
    document_version: int
    status: str
    model: str
    created_at: str
    summary: str
    report_type: str | None
    huntable: bool | None
    report: ReportAnalysis | None
    validation: AnalysisValidation | None
    error: str | None
    parse_error: str | None = None


@dataclass
class Step:
    order: int
    tactic: str
    technique_id: str
    name: str
    llm_name: str
    valid: bool
    basis: str
    quote: str
    verified: bool
    description: str
    observables: list[str]


@dataclass
class DocIndicator:
    indicator_id: int
    type: str
    value: str
    display: str
    context: str
    snippet: str
    warninglist: str | None
    first_seen: str
    last_seen: str


@dataclass
class IndicatorSummary:
    id: int
    type: str
    value: str
    display: str
    first_seen: str
    last_seen: str
    document_ids: list[int] = field(default_factory=list)
    warninglists: list[str] = field(default_factory=list)


@dataclass
class Relevance:
    document_id: int
    profile_id: str
    document_version: int
    priority: str
    score: int
    rationale: str
    matched_pirs: list[str]
    matched_technologies: list[str]
    unknowns: list[str]
    method: str
    created_at: str


@dataclass
class Query:
    id: int
    hunt_id: int
    kind: str
    title: str
    purpose: str
    kql: str
    tables: list[str]
    technique_ids: list[str]
    benign: list[str]
    pivots: list[str]
    generated_by: str
    validation_status: str
    validation: KqlValidation | None
    created_at: str

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "purpose": self.purpose,
            "generated_by": self.generated_by,
            "technique_ids": self.technique_ids,
            "tables": self.tables,
            "validation": self.validation.model_dump() if self.validation else {"status": self.validation_status},
            "benign_explanations": self.benign,
            "pivots": self.pivots,
            "kql": self.kql,
        }


@dataclass
class Hunt:
    id: int
    document_id: int
    profile_id: str
    document_version: int
    status: str
    title: str
    hypothesis: str
    package: HuntPackage | None
    package_error: str | None
    created_at: str
    updated_at: str
    queries: list[Query] = field(default_factory=list)

    @property
    def stem(self) -> str:
        return f"{self.id}-{slugify(self.title)}"

    @property
    def missing_tables(self) -> list[str]:
        return self.package.prepare.missing_tables if self.package else []


@dataclass
class TechniqueUse:
    document_id: int
    technique_id: str
    name: str
    tactic: str
    source: str
    basis: str | None
    quote: str
    verified: bool
    valid: bool


@dataclass
class Link:
    other_id: int
    reason: str
    detail: str
    score: float | None


@dataclass
class Snapshot:
    tz: ZoneInfo
    timezone: str
    generated_at: datetime
    run_id: int | None
    profiles: dict[str, Profile]
    sources: dict[str, SourceConfig]
    attack: Attack | None
    runs: list[Run]
    fetches: list[Fetch]
    docs: dict[int, Doc]
    analyses: dict[int, Analysis]
    indicators_by_doc: dict[int, list[DocIndicator]]
    indicators: list[IndicatorSummary]
    relevance_by_doc: dict[int, list[Relevance]]
    hunts: dict[int, Hunt]
    technique_uses: list[TechniqueUse]
    links_by_doc: dict[int, list[Link]]
    llm_calls: dict[str, int]

    # ------------------------------------------------------------------ lookups

    def profile_name(self, profile_id: str) -> str:
        profile = self.profiles.get(profile_id)
        return profile.name if profile else profile_id

    def hunts_for_doc(self, doc_id: int) -> list[Hunt]:
        return sorted(
            (h for h in self.hunts.values() if h.document_id == doc_id),
            key=lambda h: (h.profile_id, h.id),
        )

    def hunts_for_profile(self, profile_id: str) -> list[Hunt]:
        return sorted(
            (h for h in self.hunts.values() if h.profile_id == profile_id),
            key=lambda h: (h.updated_at, h.id),
            reverse=True,
        )

    def hunt_for(self, doc_id: int, profile_id: str) -> Hunt | None:
        return next(
            (h for h in self.hunts.values() if h.document_id == doc_id and h.profile_id == profile_id),
            None,
        )

    def relevance_for_profile(self, profile_id: str) -> list[Relevance]:
        rows = [r for rows in self.relevance_by_doc.values() for r in rows if r.profile_id == profile_id]
        return sorted(rows, key=lambda r: (PRIORITY_RANK.get(r.priority, 9), -r.score, -r.document_id))

    def max_priority(self, doc_id: int) -> Relevance | None:
        rows = self.relevance_by_doc.get(doc_id, [])
        if not rows:
            return None
        return min(rows, key=lambda r: (PRIORITY_RANK.get(r.priority, 9), -r.score))

    def assessed_doc_ids(self) -> list[int]:
        """Documents with an analysis or a relevance assessment (these get markdown briefs)."""
        ids = set(self.analyses) | set(self.relevance_by_doc)
        return sorted(i for i in ids if i in self.docs)

    def steps(self, doc_id: int) -> list[Step]:
        analysis = self.analyses.get(doc_id)
        if not analysis or not analysis.report:
            return []
        checks = {s.order: s for s in (analysis.validation.steps if analysis.validation else [])}
        steps: list[Step] = []
        for step in sorted(analysis.report.attack_steps, key=lambda s: s.order):
            check = checks.get(step.order)
            technique_id = step.technique_id.strip().upper()
            known = self.attack.get(technique_id) if self.attack else None
            if check is not None:
                valid = check.technique_valid
            elif self.attack is not None:
                valid = self.attack.is_valid(technique_id)
            else:
                valid = True
            official = (check.official_technique_name if check else None) or (known.name if known else None)
            steps.append(
                Step(
                    order=step.order,
                    tactic=canonical_tactic(step.tactic),
                    technique_id=technique_id,
                    name=official if (valid and official) else step.technique_name,
                    llm_name=step.technique_name,
                    valid=valid,
                    basis=step.basis,
                    quote=step.evidence_quote,
                    verified=bool(check and check.quote_verified),
                    description=step.description,
                    observables=list(step.observables),
                )
            )
        return steps

    def explicit_techniques(self, doc_id: int) -> list[TechniqueUse]:
        seen: dict[str, TechniqueUse] = {}
        for use in self.technique_uses:
            if use.document_id == doc_id and use.source == "explicit":
                seen.setdefault(use.technique_id, use)
        return sorted(seen.values(), key=lambda u: u.technique_id)

    def related(self, doc_id: int) -> list[tuple[Doc, list[str]]]:
        """Documents in the same cluster or directly linked, with human-readable reasons."""
        doc = self.docs.get(doc_id)
        if doc is None:
            return []
        reasons: dict[int, list[str]] = defaultdict(list)
        for link in self.links_by_doc.get(doc_id, []):
            label = {
                "near_duplicate": "near duplicate",
                "shared_indicator": "shared indicator",
                "shared_cve": "shared CVE",
            }.get(link.reason, link.reason)
            if link.detail:
                label += f" {link.detail}"
            if link.score is not None:
                label += f" (similarity {link.score:.2f})"
            reasons[link.other_id].append(label)
        if doc.duplicate_of and doc.duplicate_of in self.docs:
            reasons[doc.duplicate_of].insert(0, "this document duplicates it")
        for other in self.docs.values():
            if other.duplicate_of == doc_id:
                reasons[other.id].insert(0, "duplicate of this document")
        if doc.cluster_id is not None:
            for other in self.docs.values():
                if other.id != doc_id and other.cluster_id == doc.cluster_id:
                    reasons[other.id].append(f"same cluster ({doc.cluster_id})")
        result = [(self.docs[i], r) for i, r in reasons.items() if i in self.docs and i != doc_id]
        return sorted(result, key=lambda pair: pair[0].id)

    def kev_matches(self, profile_id: str) -> list[tuple[Doc, Relevance]]:
        rows = [
            (self.docs[r.document_id], r)
            for r in self.relevance_for_profile(profile_id)
            if r.document_id in self.docs and self.docs[r.document_id].is_kev and r.priority != "none"
        ]
        return rows

    def latest_run(self) -> Run | None:
        return self.runs[0] if self.runs else None

    def last_finished_run(self) -> Run | None:
        return next((r for r in self.runs if r.finished_at), None)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def _parse_model(model: type, raw: str | None) -> tuple[Any, str | None]:
    if not raw:
        return None, None
    try:
        return model.model_validate_json(raw), None
    except ValidationError as exc:
        return None, f"{model.__name__} did not validate: {exc.error_count()} error(s)"
    except ValueError as exc:
        return None, f"{model.__name__} is not valid JSON: {exc}"


def load_snapshot(
    conn: sqlite3.Connection,
    *,
    profiles: list[Profile],
    sources: list[SourceConfig],
    attack: Attack | None,
    timezone: str,
    now: datetime,
    run_id: int | None,
) -> Snapshot:
    tz = ZoneInfo(timezone)
    source_map = {s.id: s for s in sources}

    runs = [
        Run(
            id=row["id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            status=row["status"],
            stages=_loads(row["stages_json"], {}),
        )
        for row in conn.execute("SELECT * FROM runs ORDER BY started_at DESC, id DESC")
    ]
    fetches = [
        Fetch(
            id=row["id"],
            run_id=row["run_id"],
            source_id=row["source_id"],
            fetched_at=row["fetched_at"],
            status=row["status"],
            items_seen=row["items_seen"],
            items_new=row["items_new"],
            items_updated=row["items_updated"],
            error=row["error"],
        )
        for row in conn.execute("SELECT * FROM source_fetches ORDER BY fetched_at DESC, id DESC")
    ]

    docs: dict[int, Doc] = {}
    for row in conn.execute(
        """SELECT id, source_id, kind, tier, url, title, published_at, collected_at, updated_at,
                  version, meta_json, duplicate_of, cluster_id
           FROM documents ORDER BY id"""
    ):
        source = source_map.get(row["source_id"])
        docs[row["id"]] = Doc(
            id=row["id"],
            source_id=row["source_id"],
            source_name=source.name if source else row["source_id"],
            kind=row["kind"],
            tier=row["tier"],
            url=row["url"],
            title=row["title"],
            published_at=row["published_at"],
            collected_at=row["collected_at"],
            updated_at=row["updated_at"],
            version=row["version"],
            meta=_loads(row["meta_json"], {}),
            duplicate_of=row["duplicate_of"],
            cluster_id=row["cluster_id"],
        )

    analyses: dict[int, Analysis] = {}
    for row in conn.execute("SELECT * FROM analyses"):
        report, report_error = _parse_model(ReportAnalysis, row["analysis_json"])
        validation, validation_error = _parse_model(AnalysisValidation, row["validation_json"])
        analyses[row["document_id"]] = Analysis(
            document_id=row["document_id"],
            document_version=row["document_version"],
            status=row["status"],
            model=row["model"],
            created_at=row["created_at"],
            summary=row["summary"] or (report.summary if report else ""),
            report_type=row["report_type"] or (report.report_type if report else None),
            huntable=None if row["huntable"] is None else bool(row["huntable"]),
            report=report,
            validation=validation,
            error=row["error"],
            parse_error=report_error or validation_error,
        )

    indicators_by_doc: dict[int, list[DocIndicator]] = defaultdict(list)
    summaries: dict[int, IndicatorSummary] = {}
    for row in conn.execute(
        """SELECT i.id, i.type, i.value, i.first_seen, i.last_seen,
                  di.document_id, di.context, di.snippet, di.warninglist
           FROM indicators i JOIN document_indicators di ON di.indicator_id = i.id
           ORDER BY i.type, i.value, di.document_id"""
    ):
        display = defang(row["type"], row["value"])
        summary = summaries.get(row["id"])
        if summary is None:
            summary = summaries[row["id"]] = IndicatorSummary(
                id=row["id"],
                type=row["type"],
                value=row["value"],
                display=display,
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
            )
        summary.document_ids.append(row["document_id"])
        if row["warninglist"] and row["warninglist"] not in summary.warninglists:
            summary.warninglists.append(row["warninglist"])
        indicators_by_doc[row["document_id"]].append(
            DocIndicator(
                indicator_id=row["id"],
                type=row["type"],
                value=row["value"],
                display=display,
                context=row["context"],
                snippet=row["snippet"] or "",
                warninglist=row["warninglist"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
            )
        )

    relevance_by_doc: dict[int, list[Relevance]] = defaultdict(list)
    for row in conn.execute("SELECT * FROM relevance ORDER BY document_id, profile_id"):
        relevance_by_doc[row["document_id"]].append(
            Relevance(
                document_id=row["document_id"],
                profile_id=row["profile_id"],
                document_version=row["document_version"],
                priority=row["priority"],
                score=row["score"],
                rationale=row["rationale"],
                matched_pirs=_loads(row["matched_pirs_json"], []),
                matched_technologies=_loads(row["matched_technologies_json"], []),
                unknowns=_loads(row["unknowns_json"], []),
                method=row["method"],
                created_at=row["created_at"],
            )
        )

    hunts: dict[int, Hunt] = {}
    for row in conn.execute("SELECT * FROM hunts ORDER BY id"):
        package, package_error = _parse_model(HuntPackage, row["package_json"])
        hunts[row["id"]] = Hunt(
            id=row["id"],
            document_id=row["document_id"],
            profile_id=row["profile_id"],
            document_version=row["document_version"],
            status=row["status"],
            title=row["title"],
            hypothesis=row["hypothesis"],
            package=package,
            package_error=package_error,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
    for row in conn.execute("SELECT * FROM queries ORDER BY hunt_id, id"):
        hunt = hunts.get(row["hunt_id"])
        if hunt is None:
            continue
        validation, _ = _parse_model(KqlValidation, row["validation_json"])
        hunt.queries.append(
            Query(
                id=row["id"],
                hunt_id=row["hunt_id"],
                kind=row["kind"],
                title=row["title"],
                purpose=row["purpose"],
                kql=row["kql"],
                tables=_loads(row["tables_json"], []),
                technique_ids=_loads(row["technique_ids_json"], []),
                benign=_loads(row["benign_json"], []),
                pivots=_loads(row["pivots_json"], []),
                generated_by=row["generated_by"],
                validation_status=row["validation_status"],
                validation=validation,
                created_at=row["created_at"],
            )
        )

    step_tactics: dict[tuple[int, int], str] = {}
    for doc_id, analysis in analyses.items():
        if analysis.report:
            for step in analysis.report.attack_steps:
                step_tactics[(doc_id, step.order)] = canonical_tactic(step.tactic)
    technique_uses: list[TechniqueUse] = []
    for row in conn.execute("SELECT * FROM document_techniques ORDER BY document_id, step_order, technique_id"):
        technique_id = row["technique_id"].strip().upper()
        known = attack.get(technique_id) if attack else None
        tactic = step_tactics.get((row["document_id"], row["step_order"])) if row["source"] == "llm" else None
        if tactic is None:
            tactic = canonical_tactic(known.tactics[0]) if known and known.tactics else UNMAPPED_TACTIC
        technique_uses.append(
            TechniqueUse(
                document_id=row["document_id"],
                technique_id=technique_id,
                name=known.name if known else "",
                tactic=tactic,
                source=row["source"],
                basis=row["basis"],
                quote=row["quote"],
                verified=bool(row["quote_verified"]),
                valid=bool(row["valid"]),
            )
        )

    links_by_doc: dict[int, list[Link]] = defaultdict(list)
    for row in conn.execute("SELECT * FROM document_links"):
        links_by_doc[row["doc_a"]].append(Link(row["doc_b"], row["reason"], row["detail"], row["score"]))
        links_by_doc[row["doc_b"]].append(Link(row["doc_a"], row["reason"], row["detail"], row["score"]))

    llm_calls = {
        row["status"]: row["n"]
        for row in conn.execute("SELECT status, COUNT(*) AS n FROM llm_calls GROUP BY status")
    }

    return Snapshot(
        tz=tz,
        timezone=timezone,
        generated_at=now,
        run_id=run_id,
        profiles={p.id: p for p in profiles},
        sources=source_map,
        attack=attack,
        runs=runs,
        fetches=fetches,
        docs=docs,
        analyses=analyses,
        indicators_by_doc=dict(indicators_by_doc),
        indicators=sorted(summaries.values(), key=lambda s: (s.last_seen, s.id), reverse=True),
        relevance_by_doc=dict(relevance_by_doc),
        hunts=hunts,
        technique_uses=technique_uses,
        links_by_doc=dict(links_by_doc),
        llm_calls=llm_calls,
    )


def load_attack(ctx) -> Attack | None:
    """ATT&CK lookup if available; reports still render (with LLM-provided names) without it."""
    try:
        return ctx.attack
    except Exception as exc:  # network or cache problems must not block reporting
        ctx.log.warning("ATT&CK data unavailable, using stored technique names: %s", exc)
        return None


def snapshot_from_context(ctx, now: datetime) -> Snapshot:
    return load_snapshot(
        ctx.db,
        profiles=ctx.profiles,
        sources=ctx.sources,
        attack=load_attack(ctx),
        timezone=ctx.settings.timezone,
        now=now,
        run_id=ctx.run_id,
    )
