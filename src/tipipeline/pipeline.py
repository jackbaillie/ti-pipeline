"""Pipeline context and stage orchestration.

Each stage is a module ``tipipeline.<stage>`` exposing ``run(ctx) -> dict``
that returns JSON-serialisable stats. Stages are idempotent and re-runnable;
a failing stage is recorded and later stages still run, so one broken feed
or LLM call never blocks the rest of the cycle.
"""

from __future__ import annotations

import fcntl
import importlib
import logging
import sqlite3
import time
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from tipipeline import attack as attack_mod
from tipipeline.config import load_profiles, load_settings, load_sources, load_table_schemas
from tipipeline.db import connect, dumps, init_db, now_iso
from tipipeline.llm import CodexBackend, FakeBackend, LLMBackend
from tipipeline.models import Profile, Settings, SourceConfig

STAGES: tuple[str, ...] = (
    "collect",     # fetch sources, store/version documents
    "process",     # near-duplicate detection
    "extract",     # IOCs, CVEs, explicit ATT&CK IDs, warninglists
    "cluster",     # group documents sharing indicators/CVEs/duplicates
    "analyse",     # LLM report analysis + quote/technique validation
    "relevance",   # per-profile relevance (LLM for reports, rules for KEV)
    "hunt",        # PEAK hunt packages + KQL
    "export",      # STIX 2.1 bundles
    "report",      # markdown briefs and per-profile digests
    "dashboard",   # static HTML dashboard
)
LLM_STAGES = frozenset({"analyse", "relevance", "hunt"})

log = logging.getLogger("tipipeline")


@dataclass
class Context:
    root: Path
    settings: Settings
    sources: list[SourceConfig]
    profiles: list[Profile]
    db: sqlite3.Connection
    llm: LLMBackend
    run_id: int | None = None
    llm_enabled: bool = True
    # Optional cap on LLM documents for this run (overrides settings when set).
    llm_limit: int | None = None
    log: logging.Logger = field(default_factory=lambda: log)

    @property
    def data_dir(self) -> Path:
        return self.root / self.settings.data_dir

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def output_dir(self) -> Path:
        return self.root / self.settings.output_dir

    @property
    def max_llm_documents(self) -> int:
        return self.llm_limit if self.llm_limit is not None else self.settings.llm.max_documents_per_run

    @cached_property
    def attack(self) -> attack_mod.Attack:
        return attack_mod.load(self.cache_dir, self.settings.user_agent)

    @cached_property
    def table_schemas(self) -> dict[str, list[str]]:
        return load_table_schemas(self.root)

    def profile(self, profile_id: str) -> Profile:
        return next(p for p in self.profiles if p.id == profile_id)

    def effort(self, stage: str) -> str:
        return self.settings.llm.effort.get(stage, "medium")


def build_llm(settings: Settings) -> LLMBackend:
    if settings.llm.backend == "fake":
        return FakeBackend()
    return CodexBackend(model=settings.llm.model, timeout_seconds=settings.llm.timeout_seconds)


def open_context(root: Path, *, llm: LLMBackend | None = None, llm_enabled: bool = True) -> Context:
    settings = load_settings(root)
    conn = connect(root / settings.db_path)
    init_db(conn)
    return Context(
        root=root,
        settings=settings,
        sources=load_sources(root),
        profiles=load_profiles(root),
        db=conn,
        llm=llm or build_llm(settings),
        llm_enabled=llm_enabled,
    )


@contextmanager
def run_lock(data_dir: Path) -> Iterator[None]:
    """Prevent overlapping runs (e.g. a timer firing during a manual run)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    with open(data_dir / "pipeline.lock", "w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another pipeline run is in progress") from exc
        yield


def _flush_llm_calls(ctx: Context) -> None:
    calls = ctx.llm.drain_calls()
    if not calls:
        return
    ctx.db.executemany(
        """INSERT INTO llm_calls (run_id, task, document_id, model, effort, started_at, duration_ms, status, error)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (ctx.run_id, c.task, c.document_id, c.model, c.effort, c.started_at, c.duration_ms, c.status, c.error)
            for c in calls
        ],
    )
    ctx.db.commit()


def run_stage(ctx: Context, name: str) -> dict:
    if name not in STAGES:
        raise ValueError(f"unknown stage {name!r}; expected one of {', '.join(STAGES)}")
    started = time.monotonic()
    try:
        module = importlib.import_module(f"tipipeline.{name}")
        stats = module.run(ctx) or {}
        result = {"status": "ok", **stats}
    except Exception as exc:  # recorded, never fatal to the whole run
        ctx.db.rollback()
        ctx.log.error("stage %s failed: %s", name, exc)
        ctx.log.debug(traceback.format_exc())
        result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        _flush_llm_calls(ctx)
    result["seconds"] = round(time.monotonic() - started, 1)
    return result


def run_pipeline(ctx: Context, stages: tuple[str, ...] = STAGES) -> dict:
    with run_lock(ctx.data_dir):
        cur = ctx.db.execute("INSERT INTO runs (started_at) VALUES (?)", (now_iso(),))
        ctx.run_id = cur.lastrowid
        ctx.db.commit()
        results: dict[str, dict] = {}
        for name in stages:
            if name in LLM_STAGES and not ctx.llm_enabled and name != "relevance":
                results[name] = {"status": "skipped", "reason": "llm disabled"}
            else:
                ctx.log.info("stage %s: starting", name)
                results[name] = run_stage(ctx, name)
                ctx.log.info("stage %s: %s", name, results[name])
            # Persist progress after every stage so later stages (report, dashboard)
            # can show the current run's health.
            ctx.db.execute("UPDATE runs SET stages_json = ? WHERE id = ?", (dumps(results), ctx.run_id))
            ctx.db.commit()
        def finish() -> str:
            attempted = [r["status"] for r in results.values() if r["status"] != "skipped"]
            unhealthy = any(s in {"error", "partial", "failed"} for s in attempted)
            entirely_failed = bool(attempted) and all(s in {"error", "failed"} for s in attempted)
            status = "failed" if entirely_failed else ("partial" if unhealthy else "ok")
            ctx.db.execute(
                "UPDATE runs SET finished_at = ?, status = ?, stages_json = ? WHERE id = ?",
                (now_iso(), status, dumps(results), ctx.run_id),
            )
            ctx.db.commit()
            return status

        status = finish()
        # Static output must reflect terminal health rather than a forever-running
        # snapshot taken while its own stage was executing.
        if results.get("dashboard", {}).get("status") == "ok":
            refreshed = run_stage(ctx, "dashboard")
            if refreshed["status"] != "ok":
                results["dashboard"] = refreshed
                status = finish()
        return {"run_id": ctx.run_id, "status": status, "stages": results}
