"""Prioritised, version-driven report analysis with deterministic evidence checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta

from tipipeline.db import dumps, now_iso
from tipipeline.models import ReportAnalysis
from tipipeline.pipeline import Context
from tipipeline.relevance.rules import mentioned_technologies, prepare_text, tech_label

from .prompt import DocumentHints, build_analysis_prompt
from .validate import normalise_technique_id, validate_analysis

TIER_RANK = {"manual": 0, "research": 1, "government": 2, "news": 3}


def document_date(document: dict) -> datetime:
    """Prefer publication over collection; undated reports use collection time."""
    for field in ("published_at", "collected_at"):
        value = document.get(field)
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
            except (ValueError, TypeError):
                continue
    return datetime.min.replace(tzinfo=UTC)


def load_hints(ctx: Context, document_id: int) -> DocumentHints:
    hints = DocumentHints()
    for row in ctx.db.execute(
        """SELECT i.type, i.value, di.context, di.warninglist FROM document_indicators di
           JOIN indicators i ON i.id = di.indicator_id WHERE di.document_id = ?""", (document_id,)
    ):
        contexts = hints.indicator_counts.setdefault(row["type"], {})
        contexts[row["context"]] = contexts.get(row["context"], 0) + 1
        hints.warninglisted += bool(row["warninglist"])
        if row["type"] == "cve":
            hints.cves.append(row["value"])
    hints.cves.sort()
    hints.explicit_techniques = [row[0] for row in ctx.db.execute(
        "SELECT DISTINCT technique_id FROM document_techniques WHERE document_id = ? AND source = 'explicit' ORDER BY technique_id",
        (document_id,),
    )]
    return hints


def select_candidates(ctx: Context, *, now: datetime | None = None) -> list[dict]:
    """Manual first, then source tier, IOC-section/CVE/technology signals, recency, id.

    Publication age takes precedence over collection age: newly collected old
    articles must not consume the daily budget. Manual submissions bypass age.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(days=30)
    technologies = {tech_label(t): t for p in ctx.profiles for t in p.technologies}.values()
    candidates = []
    for row in ctx.db.execute(
        """SELECT d.* FROM documents d LEFT JOIN analyses a ON a.document_id = d.id
           WHERE d.kind IN ('article','advisory') AND d.duplicate_of IS NULL
           AND (a.document_id IS NULL OR a.document_version != d.version OR a.status = 'error')"""
    ):
        document = dict(row)
        date = document_date(document)
        if document["tier"] != "manual" and date < cutoff:
            continue
        hints = load_hints(ctx, document["id"])
        iocs = sum(c.get("ioc_section", 0) for t, c in hints.indicator_counts.items() if t != "cve")
        mentions = len(mentioned_technologies(prepare_text(document["title"], document["text"]), technologies))
        document["hints"] = hints
        document["priority_key"] = (
            TIER_RANK.get(document["tier"], 4), -iocs, -len(hints.cves), -mentions, -date.timestamp(), document["id"]
        )
        candidates.append(document)
    candidates.sort(key=lambda d: d["priority_key"])
    return candidates


def technique_catalogue(ctx: Context) -> str:
    """Ground mappings in the current cache, not in remembered/obsolete IDs."""
    return "\n".join(f"{t.id} | {t.name} | {', '.join(t.tactics)}"
                     for t in sorted(ctx.attack.techniques(), key=lambda t: t.id))


def prompt_for_document(ctx: Context, document: dict, *, catalogue: str | None = None) -> str:
    source_name = next((s.name for s in ctx.sources if s.id == document["source_id"]), document["source_id"])
    return build_analysis_prompt(
        title=document["title"], source=source_name, url=document["url"], published_at=document["published_at"],
        text=document["text"], hints=document.get("hints") or load_hints(ctx, document["id"]),
        technique_reference=catalogue if catalogue is not None else technique_catalogue(ctx),
    )


def run(ctx: Context) -> dict:
    stats = {"candidates": 0, "selected": 0, "analysed": 0, "errors": 0, "huntable": 0,
             "quotes_total": 0, "quotes_verified": 0, "quote_verification_rate": None, "invalid_technique_count": 0}
    if not ctx.llm_enabled:
        return {**stats, "skipped": "llm disabled"}
    candidates = select_candidates(ctx)
    selected = candidates[:max(0, ctx.max_llm_documents)]
    stats.update(candidates=len(candidates), selected=len(selected), deferred=len(candidates) - len(selected))
    if not selected:
        return stats
    attack = ctx.attack  # load on the main thread, not from concurrent workers
    catalogue = technique_catalogue(ctx)
    prompts = [(document, prompt_for_document(ctx, document, catalogue=catalogue)) for document in selected]
    with ThreadPoolExecutor(max_workers=max(1, ctx.settings.llm.max_concurrency)) as pool:
        futures = {pool.submit(ctx.llm.complete, task="analysis", prompt=prompt, schema=ReportAnalysis,
                               effort=ctx.effort("analysis"), document_id=document["id"]): document
                   for document, prompt in prompts}
        for future in as_completed(futures):
            document = futures[future]
            analysis = validation = None
            error = None
            try:
                analysis = future.result()
                # Use unique sequential orders and canonical IDs in stored data.
                analysis = analysis.model_copy(update={"attack_steps": [
                    step.model_copy(update={"order": index, "technique_id": normalise_technique_id(step.technique_id)})
                    for index, step in enumerate(analysis.attack_steps, 1)
                ]})
                validation = validate_analysis(analysis, document["text"], attack)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"[:2000]
                ctx.log.warning("analysis failed for document %s: %s", document["id"], error)
            ctx.db.execute("DELETE FROM document_techniques WHERE document_id = ? AND source = 'llm'", (document["id"],))
            ctx.db.execute(
                """INSERT INTO analyses (document_id, document_version, status, model, created_at, summary,
                   report_type, huntable, analysis_json, validation_json, error) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(document_id) DO UPDATE SET document_version=excluded.document_version,
                   status=excluded.status, model=excluded.model, created_at=excluded.created_at,
                   summary=excluded.summary, report_type=excluded.report_type, huntable=excluded.huntable,
                   analysis_json=excluded.analysis_json, validation_json=excluded.validation_json, error=excluded.error""",
                (document["id"], document["version"], "error" if error else "ok", ctx.llm.model, now_iso(),
                 analysis.summary if not error else "", analysis.report_type if not error else None,
                 int(analysis.huntable) if not error else None, dumps(analysis.model_dump()) if not error else None,
                 dumps(validation.model_dump()) if not error else None, error),
            )
            if error:
                stats["errors"] += 1
            else:
                for step, check in zip(analysis.attack_steps, validation.steps, strict=True):
                    ctx.db.execute(
                        """INSERT INTO document_techniques (document_id, technique_id, source, step_order, basis,
                           quote, quote_verified, valid) VALUES (?,?,'llm',?,?,?,?,?)""",
                        (document["id"], step.technique_id, step.order, step.basis, step.evidence_quote,
                         int(check.quote_verified), int(check.technique_valid)),
                    )
                stats["analysed"] += 1
                stats["huntable"] += analysis.huntable
                stats["quotes_total"] += validation.quotes_total
                stats["quotes_verified"] += validation.quotes_verified
                stats["invalid_technique_count"] += sum(not s.technique_valid for s in validation.steps)
            ctx.db.commit()
    if stats["quotes_total"]:
        stats["quote_verification_rate"] = round(stats["quotes_verified"] / stats["quotes_total"], 4)
    if stats["errors"]:
        stats["status"] = "partial" if stats["analysed"] else "error"
    return stats
