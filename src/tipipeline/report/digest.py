"""Digest window selection and per-profile digest content.

A digest covers the run window: everything collected (or updated) since the
previous run started, falling back to the last 24 hours when there is no
previous run. Documents assessed during the window are included too, so an
item whose analysis was deferred by the per-run LLM budget still reaches a
digest once it is assessed.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from tipipeline.report.data import PRIORITY_RANK, Doc, Hunt, Query, Relevance, Snapshot
from tipipeline.report.text import INDICATOR_ORDER, parse_iso

FALLBACK_HOURS = 24


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime
    label: str
    basis: str
    previous_run_id: int | None


def window_label(moment: datetime, tz: ZoneInfo) -> str:
    """``YYYY-MM-DD-am`` / ``-pm`` in the configured timezone."""
    local = moment.astimezone(tz)
    return f"{local:%Y-%m-%d}-{'am' if local.hour < 12 else 'pm'}"


def digest_window(conn: sqlite3.Connection, run_id: int | None, now: datetime, tz: ZoneInfo) -> Window:
    """Window for the current digest.

    ``run_id`` is the run producing the digest (``None`` when the stage runs on
    its own, in which case the most recent run counts as the previous one).
    """
    if run_id is not None:
        row = conn.execute(
            "SELECT id, started_at FROM runs WHERE id < ? ORDER BY id DESC LIMIT 1", (run_id,)
        ).fetchone()
    else:
        row = conn.execute("SELECT id, started_at FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    started = parse_iso(row["started_at"]) if row else None
    if started is not None and started <= now:
        return Window(
            start=started,
            end=now,
            label=window_label(now, tz),
            basis=f"since run #{row['id']} started",
            previous_run_id=row["id"],
        )
    return Window(
        start=now - timedelta(hours=FALLBACK_HOURS),
        end=now,
        label=window_label(now, tz),
        basis=f"last {FALLBACK_HOURS} hours (no previous run recorded)",
        previous_run_id=None,
    )


def _in_window(value: str | None, window: Window) -> bool:
    moment = parse_iso(value)
    return moment is not None and window.start <= moment <= window.end


def window_documents(snapshot: Snapshot, window: Window) -> list[Doc]:
    """Non-duplicate documents first collected or updated inside the window."""
    return [
        doc
        for doc in snapshot.docs.values()
        if doc.duplicate_of is None
        and (_in_window(doc.collected_at, window) or _in_window(doc.updated_at, window))
    ]


@dataclass
class DigestItem:
    doc: Doc
    relevance: Relevance
    hunt: Hunt | None
    new_in_window: bool


@dataclass
class ProfileDigest:
    profile_id: str
    window: Window
    window_doc_count: int
    assessed_count: int
    items: list[DigestItem]
    low_or_none: int
    actors: list[str]
    sectors: list[str]
    kev: list[DigestItem]
    hunts: list[Hunt]
    indicator_counts: list[tuple[str, int, int]]
    sweeps: list[tuple[Hunt, Query]] = field(default_factory=list)


def build_profile_digest(snapshot: Snapshot, profile_id: str, window: Window) -> ProfileDigest:
    window_docs = window_documents(snapshot, window)
    window_ids = {doc.id for doc in window_docs}

    assessed: list[DigestItem] = []
    for doc_id, rows in snapshot.relevance_by_doc.items():
        doc = snapshot.docs.get(doc_id)
        if doc is None or doc.duplicate_of is not None:
            continue
        for row in rows:
            if row.profile_id != profile_id:
                continue
            if doc_id in window_ids or _in_window(row.created_at, window):
                assessed.append(DigestItem(doc, row, snapshot.hunt_for(doc_id, profile_id), doc_id in window_ids))
    assessed.sort(key=lambda i: (PRIORITY_RANK.get(i.relevance.priority, 9), -i.relevance.score, -i.doc.id))

    relevant = [i for i in assessed if i.relevance.priority in ("high", "medium")]
    items = [i for i in relevant if not i.doc.is_kev]
    kev = [i for i in relevant if i.doc.is_kev]

    actors: list[str] = []
    sectors: list[str] = []
    for item in relevant:
        analysis = snapshot.analyses.get(item.doc.id)
        if analysis and analysis.report:
            for actor in analysis.report.threat_actors:
                if actor not in actors:
                    actors.append(actor)
            for sector in analysis.report.targeted_sectors:
                if sector not in sectors:
                    sectors.append(sector)

    hunts = [
        h
        for h in snapshot.hunts_for_profile(profile_id)
        if _in_window(h.updated_at, window) or _in_window(h.created_at, window)
    ]
    hunts.sort(key=lambda h: (h.status != "prepared", -h.id))
    sweeps = [(h, q) for h in hunts for q in h.queries if q.kind == "ioc_sweep"]

    total: Counter[str] = Counter()
    flagged: Counter[str] = Counter()
    seen: set[int] = set()
    for doc_id in sorted(window_ids):
        for indicator in snapshot.indicators_by_doc.get(doc_id, []):
            if indicator.indicator_id in seen:
                continue
            seen.add(indicator.indicator_id)
            total[indicator.type] += 1
    flagged_ids = {
        indicator.indicator_id
        for doc_id in window_ids
        for indicator in snapshot.indicators_by_doc.get(doc_id, [])
        if indicator.warninglist
    }
    for doc_id in window_ids:
        for indicator in snapshot.indicators_by_doc.get(doc_id, []):
            if indicator.indicator_id in flagged_ids:
                flagged_ids.discard(indicator.indicator_id)
                flagged[indicator.type] += 1
    counts = [(t, total[t], flagged[t]) for t in INDICATOR_ORDER if total[t]]

    return ProfileDigest(
        profile_id=profile_id,
        window=window,
        window_doc_count=len(window_docs),
        assessed_count=len(assessed),
        items=items,
        low_or_none=len(assessed) - len(relevant),
        actors=actors,
        sectors=sectors,
        kev=kev,
        hunts=hunts,
        indicator_counts=counts,
        sweeps=sweeps,
    )
