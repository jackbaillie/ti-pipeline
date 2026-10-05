"""Prepare per-customer PEAK hunt packages and KQL (nothing is executed)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from tipipeline.db import dumps, now_iso
from tipipeline.hunt.package import build_package
from tipipeline.hunt.prompt import build_prompt
from tipipeline.models import AnalysisValidation, HuntDraft, ReportAnalysis
from tipipeline.pipeline import Context


def _knowledge(ctx: Context, document: dict, profile_id: str) -> list[str]:
    cluster = document["cluster_id"]
    if cluster is None:
        return []
    related = ctx.db.execute(
        "SELECT id, title, url FROM documents WHERE cluster_id = ? AND id != ? ORDER BY id",
        (cluster, document["id"]),
    ).fetchall()
    notes = [f"Related report in cluster {cluster}: [{r['id']}] {r['title']} ({r['url']}). Correlation is contextual, not proof of a common actor." for r in related]
    earlier = ctx.db.execute(
        """SELECT h.id, h.title, h.status, h.document_version FROM hunts h
           JOIN documents d ON d.id = h.document_id
           WHERE d.cluster_id = ? AND h.profile_id = ?
           AND (h.document_id != ? OR h.document_version < ?) ORDER BY h.id""",
        (cluster, profile_id, document["id"], document["version"]),
    ).fetchall()
    notes.extend(f"Earlier prepared hunt in this cluster for this profile: [{r['id']}] {r['title']} (source version {r['document_version']}; status {r['status']}). Preparation is not an execution result." for r in earlier)
    return notes


def _store(ctx: Context, document: dict, package, queries) -> None:
    now = now_iso()
    # A new source version replaces the prepared package, not an executed result.
    ctx.db.execute(
        """INSERT INTO hunts (document_id, profile_id, document_version, status, title, hypothesis,
                               package_json, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(document_id, profile_id) DO UPDATE SET
             document_version=excluded.document_version, status=excluded.status, title=excluded.title,
             hypothesis=excluded.hypothesis, package_json=excluded.package_json, updated_at=excluded.updated_at""",
        (document["id"], package.profile_id, document["version"], package.status, package.title,
         package.prepare.hypothesis, dumps(package.model_dump()), now, now),
    )
    hunt_id = ctx.db.execute("SELECT id FROM hunts WHERE document_id=? AND profile_id=?", (document["id"], package.profile_id)).fetchone()["id"]
    ctx.db.execute("DELETE FROM queries WHERE hunt_id=?", (hunt_id,))
    ctx.db.executemany(
        """INSERT INTO queries (hunt_id, kind, title, purpose, kql, tables_json, technique_ids_json,
                 benign_json, pivots_json, generated_by, validation_status, validation_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [(hunt_id, q.kind, q.query.title, q.query.purpose, q.query.kql, dumps(q.query.tables),
          dumps(q.query.technique_ids), dumps(q.query.benign_explanations), dumps(q.query.pivots),
          q.generated_by, q.validation.status, dumps(q.validation.model_dump()), now) for q in queries],
    )


def run(ctx: Context) -> dict:
    rows = ctx.db.execute(
        """SELECT d.*, a.analysis_json, a.validation_json, r.profile_id,
                  r.priority, r.score, r.rationale, r.matched_pirs_json
           FROM documents d
           JOIN analyses a ON a.document_id=d.id AND a.document_version=d.version
           JOIN relevance r ON r.document_id=d.id AND r.document_version=d.version
           LEFT JOIN hunts h ON h.document_id=d.id AND h.profile_id=r.profile_id
           WHERE a.status='ok' AND a.huntable=1 AND r.priority IN ('high','medium')
             AND (h.id IS NULL OR h.document_version != d.version)
           ORDER BY CASE r.priority WHEN 'high' THEN 0 ELSE 1 END, r.score DESC,
                    d.published_at DESC, d.id, r.profile_id"""
    ).fetchall()
    profiles = {p.id: p for p in ctx.profiles}
    grouped = {}
    for row in rows:
        if row["profile_id"] not in profiles:
            continue
        doc = grouped.setdefault(row["id"], {"document": dict(row), "relevance": []})
        doc["relevance"].append(dict(row))
    stats = {
        "candidate_documents": len(grouped), "candidate_pairs": sum(len(g["relevance"]) for g in grouped.values()),
        "drafted_documents": 0, "hunts": 0, "prepared": 0, "insufficient_telemetry": 0,
        "queries": 0, "errors": 0, "deferred_documents": 0,
    }
    if not ctx.llm_enabled:
        return dict(stats, skipped="llm disabled")
    selected = list(grouped.values())[:max(0, ctx.max_llm_documents)]
    stats["deferred_documents"] = len(grouped) - len(selected)
    if not selected:
        return stats
    # Load schemas/ATT&CK on the main thread; worker threads only call the LLM.
    schemas, attack = ctx.table_schemas, ctx.attack
    jobs = []
    for group in selected:
        document = group["document"]
        try:
            analysis = ReportAnalysis.model_validate_json(document["analysis_json"])
            validation = AnalysisValidation.model_validate_json(document["validation_json"])
        except (ValueError, TypeError) as exc:
            ctx.log.error("hunt: document %s has invalid stored analysis/validation: %s", document["id"], exc)
            stats["errors"] += 1
            continue
        indicators = [dict(r) for r in ctx.db.execute(
            """SELECT i.type, i.value, di.warninglist FROM document_indicators di
               JOIN indicators i ON i.id=di.indicator_id
               WHERE di.document_id=? AND di.warninglist IS NULL ORDER BY i.type, i.value""",
            (document["id"],),
        )]
        candidate_profiles = [profiles[r["profile_id"]] for r in group["relevance"]]
        prompt = build_prompt(document, analysis, validation, indicators, candidate_profiles, schemas)
        jobs.append((group, analysis, validation, indicators, prompt))
    with ThreadPoolExecutor(max_workers=max(1, ctx.settings.llm.max_concurrency)) as executor:
        futures = {
            executor.submit(ctx.llm.complete, task="hunt", prompt=job[4], schema=HuntDraft,
                            effort=ctx.effort("hunt"), document_id=job[0]["document"]["id"]): job
            for job in jobs
        }
        for future in as_completed(futures):
            group, analysis, validation, indicators, _ = futures[future]
            document = group["document"]
            try:
                draft = future.result()
            except Exception as exc:
                ctx.log.error("hunt: document %s LLM drafting failed: %s", document["id"], exc)
                stats["errors"] += 1
                continue
            stats["drafted_documents"] += 1
            for relevance in group["relevance"]:
                profile = profiles[relevance["profile_id"]]
                package, queries = build_package(
                    document=document, profile=profile, relevance=relevance, analysis=analysis,
                    validation=validation, draft=draft, indicators=indicators, schemas=schemas,
                    attack=attack, knowledge=_knowledge(ctx, document, profile.id),
                )
                _store(ctx, document, package, queries)
                stats["hunts"] += 1
                stats[package.status] += 1
                stats["queries"] += len(queries)
            ctx.db.commit()
    if stats["errors"]:
        stats["status"] = "partial" if stats["hunts"] else "error"
    return stats
