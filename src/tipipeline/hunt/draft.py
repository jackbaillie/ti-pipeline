"""Draft one hunt with the LLM, check its KQL against the catalogue, repair once, drop what still fails.

Shared by the per-customer hunt stage and manual investigations. No database access here, so
it can run on worker threads once ``ctx.table_schemas`` and ``ctx.attack`` are loaded.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from tipipeline.attack import Attack
from tipipeline.hunt.kql import rewrite_lookback, validate_kql
from tipipeline.hunt.prompt import build_prompt, build_repair_prompt
from tipipeline.hunt.templates import PYRAMID_LEVELS, build_sweeps
from tipipeline.models import (
    AnalysisValidation, DraftQuery, HuntDraft, HuntEvidence, HuntTechnique, KqlValidation,
    Profile, QueryRepair, ReportAnalysis,
)
from tipipeline.pipeline import Context


@dataclass(frozen=True)
class ReportInput:
    document: dict  # needs id, title, url, source_id, published_at
    analysis: ReportAnalysis
    validation: AnalysisValidation | None = None


@dataclass(frozen=True)
class PreparedQuery:
    query: DraftQuery
    validation: KqlValidation
    kind: str  # behavioural | ioc_sweep
    generated_by: str  # llm | template


@dataclass
class DraftResult:
    title: str
    hypothesis: str
    scope: str
    pyramid_levels: list[str]
    techniques: list[HuntTechnique]
    evidence: list[HuntEvidence]
    # Schema-valid only: behavioural queries first, then IOC sweeps.
    queries: list[PreparedQuery]
    gaps: list[str]
    # Queries that still failed the schema check after the single repair call.
    dropped: int
    # True when a repair call was made (some draft query failed the first check).
    repaired: bool


def hunt_indicators(conn: sqlite3.Connection, document_ids: Iterable[int], *, include_scraped: bool) -> list[dict]:
    """IOCs for sweeps: from IOC sections and feeds, plus body text when asked; never benign-flagged ones."""
    ids = sorted(set(document_ids))
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f"""SELECT i.type, i.value, MAX(di.context) AS context FROM document_indicators di
            JOIN indicators i ON i.id = di.indicator_id
            WHERE di.document_id IN ({marks}) AND di.warninglist IS NULL
              AND (di.context IN ('ioc_section', 'feed') OR (? AND di.context = 'body'))
            GROUP BY i.id ORDER BY i.type, i.value""",
        (*ids, int(include_scraped)),
    )
    return [dict(r) for r in rows]


def _prepare(query: DraftQuery, schemas: dict[str, list[str]], attack: Attack, days: int) -> PreparedQuery:
    kql = rewrite_lookback(query.kql, days)
    checked = validate_kql(kql, schemas)
    query = query.model_copy(update={
        "kql": kql, "tables": checked.tables,
        "technique_ids": sorted({i.upper() for i in query.technique_ids if attack.is_valid(i)}),
    })
    return PreparedQuery(query, checked, "behavioural", "llm")


def _techniques(queries: list[PreparedQuery], reports: Sequence[ReportInput], attack: Attack) -> list[HuntTechnique]:
    stated = {s.technique_id.upper(): s.tactic for r in reports for s in r.analysis.attack_steps}
    techniques = {}
    for q in queries:
        for technique_id in q.query.technique_ids:
            technique = attack.get(technique_id)
            if technique is None or technique.deprecated or technique.id in techniques:
                continue
            tactic = stated.get(technique.id, "")
            tactic = next((t for t in technique.tactics if t.casefold() == tactic.casefold()), None)
            tactic = tactic or (technique.tactics[0] if technique.tactics else stated.get(technique.id, ""))
            techniques[technique.id] = HuntTechnique(id=technique.id, name=technique.name, tactic=tactic)
    return list(techniques.values())


def _evidence(reports: Sequence[ReportInput], techniques: list[HuntTechnique]) -> list[HuntEvidence]:
    """Quotes for the steps this hunt tests; all steps when none match, except for roundups."""
    bases = {t.id.split(".")[0] for t in techniques}
    evidence = []
    for r in reports:
        verified = {s.order: s.quote_verified for s in r.validation.steps} if r.validation else {}
        steps = [s for s in r.analysis.attack_steps if s.technique_id.upper().split(".")[0] in bases]
        if not steps and r.analysis.report_type != "roundup":
            steps = r.analysis.attack_steps
        evidence += [HuntEvidence(quote=s.evidence_quote, verified=verified.get(s.order, False)) for s in steps]
    return evidence


def draft_hunt(
    ctx: Context, *, focus: str, reports: Sequence[ReportInput], indicators: Sequence[dict],
    profile: Profile | None = None, matched_pirs: Sequence[str] = (), matched_technologies: Sequence[str] = (),
    document_id: int | None = None,
) -> DraftResult:
    """Draft, check and repair one hunt. Raises if the drafting call fails; a failed repair drops the bad queries."""
    schemas, attack, days = ctx.table_schemas, ctx.attack, ctx.settings.hunt.lookback_days
    prompt = build_prompt(
        focus=focus, reports=reports, indicators=indicators, profile=profile, matched_pirs=matched_pirs,
        matched_technologies=matched_technologies, themes=ctx.themes, schemas=schemas, lookback_days=days,
    )
    draft = ctx.llm.complete(task="hunt", prompt=prompt, schema=HuntDraft, effort=ctx.effort("hunt"), document_id=document_id)
    prepared = [_prepare(q, schemas, attack, days) for q in draft.queries]
    failed = [i for i, p in enumerate(prepared) if p.validation.status != "schema_valid"]
    repaired = False
    if failed:
        repaired = True
        try:
            fix = ctx.llm.complete(
                task="hunt_repair", prompt=build_repair_prompt([(prepared[i].query, prepared[i].validation) for i in failed], schemas, days),
                schema=QueryRepair, effort=ctx.effort("hunt_repair"), document_id=document_id,
            )
        except Exception as exc:
            ctx.log.warning("hunt: KQL repair failed for document %s: %s", document_id, exc)
        else:
            for i, query in zip(failed, fix.queries):
                prepared[i] = _prepare(query, schemas, attack, days)
    sweeps = build_sweeps(indicators, days)
    prepared += [PreparedQuery(s.query, validate_kql(s.query.kql, schemas), s.kind, s.generated_by) for s in sweeps]
    queries = [p for p in prepared if p.validation.status == "schema_valid"]
    gaps = [
        f"Dropped query '{p.query.title}': {' '.join(p.validation.messages)}"
        for p in prepared if p.validation.status != "schema_valid"
    ]
    if not queries:
        gaps.append("No query passed the schema check. Write the hunt queries by hand.")
    if profile and any(t.exposure == "ot" for t in profile.technologies):
        gaps.append("IT endpoint, identity and perimeter logs do not show OT activity. Confirm plant-floor coverage before reading a clean result as no OT activity.")
    techniques = _techniques(queries, reports, attack)
    return DraftResult(
        title=draft.title, hypothesis=draft.hypothesis, scope=draft.scope,
        pyramid_levels=list(dict.fromkeys(draft.pyramid_levels + [PYRAMID_LEVELS[s.family] for s in sweeps])),
        techniques=techniques, evidence=_evidence(reports, techniques), queries=queries, gaps=gaps,
        dropped=len(prepared) - len(queries), repaired=repaired,
    )
