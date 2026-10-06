"""Investigation pages: the form with recent investigations, and one page per investigation.

The dashboard stage writes static copies alongside every other page.
``ti-pipeline serve`` renders the same templates from the database on each
request, so a running investigation's page is never stale and never waits for
the pipeline's next render.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment

from tipipeline.dashboard import page_shell
from tipipeline.investigate import (
    KIND_LABELS,
    MAX_INPUT_LENGTH,
    Investigation,
    get_investigation,
    list_investigations,
)

REFRESH_SECONDS = 5
RECENT_LIMIT = 50


def render_pages(ctx, env: Environment, common: dict) -> dict[str, str]:
    """Static copies for the dashboard stage, keyed by path under ``output/dashboard``."""
    investigations = list_investigations(ctx.db)
    files = {"investigate.html": render_form(ctx, env, common, live=False, recent=investigations[:RECENT_LIMIT])}
    for investigation in investigations:
        # Every document in the database gets a page in the same render.
        files[f"investigations/{investigation.id}.html"] = render_investigation(
            ctx, env, common, investigation, live=False, has_document_page=lambda _: True
        )
    return files


def render_form(
    ctx, env: Environment, common: dict, *, live: bool, recent: list[Investigation] | None = None,
    error: str | None = None, values: dict | None = None,
) -> str:
    """The investigate page. Static copies say that submitting needs the server."""
    values = values or {
        "value": "", "kind": "auto", "customer": "", "include_scraped": ctx.settings.hunt.include_scraped_iocs,
    }
    return env.get_template("investigate.html").render(
        **common, base="", active="investigate", live=live, error=error, values=values,
        kinds=KIND_LABELS, profiles=ctx.profiles, max_length=MAX_INPUT_LENGTH,
        recent=list_investigations(ctx.db, RECENT_LIMIT) if recent is None else recent,
    )


def render_investigation(
    ctx, env: Environment, common: dict, investigation: Investigation, *, live: bool,
    has_document_page: Callable[[int], bool],
) -> str:
    result = investigation.result or {}
    hunt = result.get("hunt") or {}
    if hunt:
        hunt = {**hunt, "sources": [
            {**source, "href": f"../documents/{source['id']}.html" if has_document_page(source["id"]) else None}
            for source in hunt.get("sources", [])
        ]}
    queries = hunt.get("queries", [])
    profile = next((p for p in ctx.profiles if p.id == investigation.profile_id), None)
    stories = [
        {**story, "reports": [
            {**report, "href": f"../documents/{report['id']}.html" if has_document_page(report["id"]) else None}
            for report in story["reports"]
        ]}
        for story in result.get("stories", [])
    ]
    kev = result.get("kev")
    if kev:
        kev = {**kev, "href": f"../documents/{kev['document_id']}.html" if has_document_page(kev["document_id"]) else None}
    return env.get_template("investigation.html").render(
        **common, base="../", active="investigate", live=live,
        refresh=REFRESH_SECONDS if live and investigation.active else None,
        inv=investigation, result=result, stories=stories, kev=kev, hunt=hunt or None,
        behavioural=[q for q in queries if q["kind"] == "behavioural"],
        sweeps=[q for q in queries if q["kind"] == "ioc_sweep"],
        kind_label=KIND_LABELS.get(investigation.kind, investigation.kind),
        customer=profile.name if profile else (investigation.profile_id or "General investigation"),
    )


def _document_pages(ctx) -> Callable[[int], bool]:
    """Pages written by the last dashboard render; reports collected since then have none yet."""
    folder = ctx.output_dir / "dashboard" / "documents"
    return lambda document_id: (folder / f"{document_id}.html").is_file()


def live_form(ctx, *, error: str | None = None, values: dict | None = None) -> str:
    env, common = page_shell(ctx, datetime.now(UTC))
    return render_form(ctx, env, common, live=True, error=error, values=values)


def live_investigation(ctx, investigation_id: int) -> str | None:
    investigation = get_investigation(ctx.db, investigation_id)
    if investigation is None:
        return None
    env, common = page_shell(ctx, datetime.now(UTC))
    return render_investigation(ctx, env, common, investigation, live=True, has_document_page=_document_pages(ctx))


def write_investigation_page(ctx, investigation_id: int) -> Path:
    """Write one static investigation page (used by the CLI) and return its path."""
    investigation = get_investigation(ctx.db, investigation_id)
    if investigation is None:
        raise LookupError(f"investigation {investigation_id} does not exist")
    env, common = page_shell(ctx, datetime.now(UTC))
    path = ctx.output_dir / "dashboard" / "investigations" / f"{investigation_id}.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_investigation(ctx, env, common, investigation, live=False, has_document_page=_document_pages(ctx)),
        encoding="utf-8",
    )
    return path
