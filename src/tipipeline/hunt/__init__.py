"""Prepare one PEAK hunt package with KQL per relevant (report, customer) pair (nothing is executed)."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from tipipeline.db import dumps, now_iso
from tipipeline.hunt.draft import ReportInput, draft_hunt, hunt_indicators
from tipipeline.hunt.package import build_package
from tipipeline.models import AnalysisValidation, ReportAnalysis
from tipipeline.pipeline import Context


def _related_note(row) -> str:
    return f"Related report [{row['id']}]: {row['title']} ({row['url']})"


def _earlier_hunt_note(row) -> str:
    return f"Earlier hunt #{row['id']} for this profile: {row['title']} (source version {row['document_version']}, {row['status']})"


def _knowledge(ctx: Context, document: dict, profile_id: str) -> list[str]:
    cluster = document["cluster_id"]
    if cluster is None:
        return []
    related = ctx.db.execute(
        "SELECT id, title, url FROM documents WHERE cluster_id = ? AND id != ? ORDER BY id",
        (cluster, document["id"]),
    ).fetchall()
    earlier = ctx.db.execute(
        """SELECT h.id, h.title, h.status, h.document_version FROM hunts h
           JOIN documents d ON d.id = h.document_id
           WHERE d.cluster_id = ? AND h.profile_id = ?
           AND (h.document_id != ? OR h.document_version < ?) ORDER BY h.id""",
        (cluster, profile_id, document["id"], document["version"]),
    ).fetchall()
    return [_related_note(r) for r in related] + [_earlier_hunt_note(r) for r in earlier]


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
        """SELECT d.*, a.analysis_json, a.validation_json, r.profile_id, r.priority, r.score,
                  r.rationale, r.matched_pirs_json, r.matched_technologies_json
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
    pairs = [dict(r) for r in rows if r["profile_id"] in profiles]
    stats = {
        "candidate_pairs": len(pairs), "deferred_pairs": 0, "hunts": 0, "repairs": 0,
        "queries": 0, "queries_dropped": 0, "errors": 0,
    }
    if not ctx.llm_enabled:
        return dict(stats, skipped="llm disabled")
    # The per-run LLM cap counts (report, customer) pairs; repair calls are not counted.
    selected = pairs[:max(0, ctx.max_llm_documents)]
    stats["deferred_pairs"] = len(pairs) - len(selected)
    if not selected:
        return stats
    # Load schemas/ATT&CK on the main thread; worker threads only call the LLM.
    _ = ctx.table_schemas, ctx.attack
    jobs = []
    indicators: dict[int, list[dict]] = {}
    for pair in selected:
        try:
            report = ReportInput(
                document=pair, analysis=ReportAnalysis.model_validate_json(pair["analysis_json"]),
                validation=AnalysisValidation.model_validate_json(pair["validation_json"]),
            )
        except (ValueError, TypeError) as exc:
            ctx.log.error("hunt: document %s has invalid stored analysis/validation: %s", pair["id"], exc)
            stats["errors"] += 1
            continue
        if pair["id"] not in indicators:
            indicators[pair["id"]] = hunt_indicators(ctx.db, [pair["id"]], include_scraped=ctx.settings.hunt.include_scraped_iocs)
        jobs.append((pair, report))
    with ThreadPoolExecutor(max_workers=max(1, ctx.settings.llm.max_concurrency)) as executor:
        futures = {
            executor.submit(
                draft_hunt, ctx, focus=pair["rationale"], reports=[report], indicators=indicators[pair["id"]],
                profile=profiles[pair["profile_id"]], matched_pirs=json.loads(pair["matched_pirs_json"]),
                matched_technologies=json.loads(pair["matched_technologies_json"]), document_id=pair["id"],
            ): pair
            for pair, report in jobs
        }
        for future in as_completed(futures):
            pair = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                ctx.log.error("hunt: document %s for %s LLM drafting failed: %s", pair["id"], pair["profile_id"], exc)
                stats["errors"] += 1
                continue
            stats["repairs"] += result.repaired
            stats["queries_dropped"] += result.dropped
            if not result.queries:
                ctx.log.error("hunt: document %s for %s produced no schema-valid queries", pair["id"], pair["profile_id"])
                stats["errors"] += 1
                continue
            profile = profiles[pair["profile_id"]]
            package = build_package(
                document=pair, profile=profile, relevance=pair, result=result,
                knowledge=_knowledge(ctx, pair, profile.id),
            )
            _store(ctx, pair, package, result.queries)
            ctx.db.commit()
            stats["hunts"] += 1
            stats["queries"] += len(result.queries)
    if stats["errors"]:
        stats["status"] = "partial" if stats["hunts"] else "error"
    return stats
