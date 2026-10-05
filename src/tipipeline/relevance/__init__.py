"""Version-driven customer relevance: rules for KEV, one LLM call per analysed report."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from tipipeline.db import dumps, now_iso
from tipipeline.models import Profile, ProfileAssessment, ReportAnalysis, RelevanceResult
from tipipeline.pipeline import Context

from .prompt import build_relevance_prompt
from .rules import (RuleSignals, assess_from_signals, assess_kev, kev_record, prepare_text, signals_for_analysis)


def sanitise_assessments(result: RelevanceResult, profiles: list[Profile], analysis: ReportAnalysis,
                         signals: list[RuleSignals]) -> list[tuple[ProfileAssessment, str]]:
    """Discard unknown/duplicate profile IDs, bound scores and fill missing profiles.

    Missing profiles carry method='rules', honestly identifying their provenance.
    """
    configured = {p.id: p for p in profiles}
    signal_map = {s.profile_id: s for s in signals}
    supplied: dict[str, ProfileAssessment] = {}
    for assessment in result.assessments:
        if assessment.profile_id not in configured or assessment.profile_id in supplied:
            continue
        profile = configured[assessment.profile_id]
        valid_pirs = {p.id for p in profile.pirs}
        supplied[profile.id] = assessment.model_copy(update={
            "score": min(100, max(0, assessment.score)),
            "matched_pirs": list(dict.fromkeys(p for p in assessment.matched_pirs if p in valid_pirs)),
            "matched_technologies": list(dict.fromkeys(assessment.matched_technologies)),
            "unknowns": list(dict.fromkeys(assessment.unknowns)),
        })
    return [(supplied[p.id], "llm") if p.id in supplied else
            (assess_from_signals(p, signal_map[p.id], analysis), "rules") for p in profiles]


def store_assessment(ctx: Context, document: dict, assessment: ProfileAssessment, method: str) -> None:
    ctx.db.execute(
        """INSERT INTO relevance (document_id, profile_id, document_version, priority, score, rationale,
           matched_pirs_json, matched_technologies_json, unknowns_json, method, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(document_id, profile_id) DO UPDATE SET
           document_version=excluded.document_version, priority=excluded.priority, score=excluded.score,
           rationale=excluded.rationale, matched_pirs_json=excluded.matched_pirs_json,
           matched_technologies_json=excluded.matched_technologies_json, unknowns_json=excluded.unknowns_json,
           method=excluded.method, created_at=excluded.created_at""",
        (document["id"], assessment.profile_id, document["version"], assessment.priority, assessment.score,
         assessment.rationale, dumps(assessment.matched_pirs), dumps(assessment.matched_technologies),
         dumps(assessment.unknowns), method, now_iso()),
    )


def run(ctx: Context) -> dict:
    stats = {"kev_documents": 0, "llm_documents": 0, "assessments": 0, "rules_fallbacks": 0,
             "errors": 0, "deferred": 0, "by_priority": {p: 0 for p in ("high", "medium", "low", "none")}}
    if not ctx.profiles:
        return stats
    current = {(r["document_id"], r["profile_id"], r["document_version"]) for r in ctx.db.execute(
        "SELECT document_id, profile_id, document_version FROM relevance")}

    def pending(document: dict) -> bool:
        return any((document["id"], p.id, document["version"]) not in current for p in ctx.profiles)

    def persist(document: dict, assessment: ProfileAssessment, method: str) -> None:
        store_assessment(ctx, document, assessment, method)
        stats["assessments"] += 1
        stats["by_priority"][assessment.priority] += 1

    kev_cves = set()
    for row in ctx.db.execute("SELECT * FROM documents WHERE kind='vulnerability' AND duplicate_of IS NULL"):
        document = dict(row)
        kev = kev_record(json.loads(document["meta_json"]))
        # Only raw KEV records qualify; unrelated vulnerability sources do not.
        if not kev["cveID"] or not kev["dateAdded"]:
            continue
        kev_cves.add(kev["cveID"].upper())
        if not pending(document):
            continue
        for profile in ctx.profiles:
            if (document["id"], profile.id, document["version"]) not in current:
                persist(document, assess_kev(profile, kev, document["text"]), "rules")
        stats["kev_documents"] += 1
        ctx.db.commit()
    if not ctx.llm_enabled:
        return stats
    # Local import avoids an import cycle: analysis selection reuses relevance rules.
    from tipipeline.analyse import TIER_RANK, document_date
    candidates = [dict(r) for r in ctx.db.execute(
        """SELECT d.*, a.analysis_json FROM documents d JOIN analyses a ON a.document_id=d.id
           WHERE a.status='ok' AND a.document_version=d.version AND d.duplicate_of IS NULL"""
    ) if pending(dict(r))]
    candidates.sort(key=lambda d: (TIER_RANK.get(d["tier"], 4), -document_date(d).timestamp(), d["id"]))
    selected = candidates[:max(0, ctx.max_llm_documents)]
    stats["deferred"] = len(candidates) - len(selected)
    jobs = []
    for document in selected:
        analysis = ReportAnalysis.model_validate_json(document["analysis_json"])
        prepared = prepare_text(document["title"], document["text"])
        signals = [signals_for_analysis(p, analysis, prepared, kev_cves) for p in ctx.profiles]
        prompt = build_relevance_prompt(document=document, analysis=analysis, profiles=ctx.profiles, signals=signals)
        jobs.append((document, analysis, signals, prompt))
    with ThreadPoolExecutor(max_workers=max(1, ctx.settings.llm.max_concurrency)) as pool:
        futures = {pool.submit(ctx.llm.complete, task="relevance", prompt=prompt, schema=RelevanceResult,
                               effort=ctx.effort("relevance"), document_id=d["id"]): (d, analysis, signals)
                   for d, analysis, signals, prompt in jobs}
        for future in as_completed(futures):
            document, analysis, signals = futures[future]
            try:
                assessments = sanitise_assessments(future.result(), ctx.profiles, analysis, signals)
            except Exception as exc:
                ctx.log.warning("relevance failed for document %s: %s", document["id"], exc)
                stats["errors"] += 1
                continue  # no rows: retry on the next run
            for assessment, method in assessments:
                persist(document, assessment, method)
                stats["rules_fallbacks"] += method == "rules"
            stats["llm_documents"] += 1
            ctx.db.commit()
    if stats["errors"]:
        stats["status"] = "partial" if stats["assessments"] else "error"
    return stats
