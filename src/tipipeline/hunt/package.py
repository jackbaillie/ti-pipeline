"""Apply a shared draft to one profile and build its PEAK package."""
from __future__ import annotations

import json
from dataclasses import dataclass

from tipipeline.attack import Attack
from tipipeline.hunt.kql import rewrite_lookback, validate_kql, lookback_days
from tipipeline.hunt.templates import FAMILIES, PYRAMID_LEVELS, build_sweeps, indicator_values
from tipipeline.models import (
    ActPhase, AnalysisValidation, DraftQuery, HuntDraft, HuntEvidence, HuntPackage,
    HuntTechnique, HuntTrigger, KqlValidation, PreparePhase, Profile, ReportAnalysis,
)


@dataclass
class PreparedQuery:
    query: DraftQuery
    validation: KqlValidation
    kind: str
    generated_by: str


def build_package(
    *, document: dict, profile: Profile, relevance: dict, analysis: ReportAnalysis,
    validation: AnalysisValidation, draft: HuntDraft, indicators: list[dict],
    schemas: dict[str, list[str]], attack: Attack, knowledge: list[str],
) -> tuple[HuntPackage, list[PreparedQuery]]:
    queries: list[PreparedQuery] = []
    gaps = []
    for q in draft.queries:
        kql = rewrite_lookback(q.kql, profile.retention_days)
        checked = validate_kql(kql, schemas, profile.telemetry)
        query = q.model_copy(update={
            "kql": kql, "tables": checked.tables,
            "technique_ids": sorted({i.upper() for i in q.technique_ids if attack.is_valid(i)}),
        })
        queries.append(PreparedQuery(query, checked, "behavioural", "llm"))
        if checked.unavailable_tables:
            gaps.append(f"Cannot test '{q.title}': requires {', '.join(checked.unavailable_tables)} which {profile.name} does not collect.")
        if checked.unknown_tables:
            gaps.append(f"Cannot test '{q.title}': unrecognised tables {', '.join(checked.unknown_tables)} need schema review.")
        if not checked.tables:
            gaps.append(f"Cannot test '{q.title}': no identifiable input table; manual KQL review required.")
        if checked.unknown_columns:
            gaps.append(f"Review '{q.title}' before execution: apparent unknown columns {', '.join(checked.unknown_columns)}; schema checking cannot establish syntax or types.")
    sweeps = build_sweeps(profile, indicators)
    for sweep in sweeps:
        checked = validate_kql(sweep.query.kql, schemas, profile.telemetry)
        queries.append(PreparedQuery(sweep.query, checked, sweep.kind, sweep.generated_by))
    for family in FAMILIES:
        if indicator_values(indicators, family) and not any(s.family == family for s in sweeps):
            gaps.append(f"No {family} IOC sweep available: {profile.name} collects none of the supported tables for this indicator family.")
    if any(t.exposure == "ot" for t in profile.technologies):
        gaps.append("IT endpoint, identity and perimeter logs do not establish OT visibility. Confirm plant-floor coverage before interpreting a negative hunt result as absence of OT activity.")
    required = sorted({t for q in queries for t in q.validation.tables})
    available = sorted(set(required) & set(profile.telemetry))
    missing = sorted(set(required) - set(profile.telemetry))
    techniques = {}
    for step in analysis.attack_steps:
        technique = attack.get(step.technique_id)
        if technique and not technique.deprecated:
            tactic = next((t for t in technique.tactics if t.casefold() == step.tactic.casefold()), None)
            tactic = tactic or (technique.tactics[0] if technique.tactics else step.tactic)
            techniques[technique.id] = HuntTechnique(id=technique.id, name=technique.name, tactic=tactic)
    verified = {s.order: s.quote_verified for s in validation.steps}
    levels = list(dict.fromkeys(draft.pyramid_levels + [PYRAMID_LEVELS[s.family] for s in sweeps]))
    package = HuntPackage(
        document_id=document["id"], profile_id=profile.id, title=draft.title,
        status="prepared" if any(q.validation.status != "invalid" for q in queries) else "insufficient_telemetry",
        prepare=PreparePhase(
            trigger=HuntTrigger(
                document_id=document["id"], title=document["title"], url=document["url"],
                source_id=document["source_id"], published_at=document["published_at"],
            ),
            priority=relevance["priority"], relevance_rationale=relevance["rationale"],
            matched_pirs=json.loads(relevance["matched_pirs_json"]), hypothesis=draft.hypothesis,
            scope=f"{draft.scope}\nEnvironment: {profile.name}; behavioural window {profile.retention_days} days; IOC sweep window {lookback_days(profile.retention_days)} days.",
            techniques=list(techniques.values()), pyramid_levels=levels, required_tables=required,
            available_tables=available, missing_tables=missing,
            evidence=[HuntEvidence(quote=s.evidence_quote, verified=verified.get(s.order, False)) for s in analysis.attack_steps],
        ),
        act=ActPhase(gaps=gaps), knowledge=knowledge,
    )
    return package, queries
