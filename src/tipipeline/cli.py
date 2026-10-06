"""Command-line interface: ``ti-pipeline <command>``."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from tipipeline.config import repo_root
from tipipeline.pipeline import STAGES, open_context, run_pipeline, run_lock, run_stage

app = typer.Typer(add_completion=False, help="Intelligence-led threat hunting pipeline.")
console = Console()


def _load_env(root: Path) -> None:
    """Load ``KEY=VALUE`` lines from ``.env`` without overriding the real environment."""
    path = root / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _setup_logging(root: Path, verbose: bool) -> None:
    _load_env(root)
    logs = root / "data" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(logs / "pipeline.log")],
    )
    # Keep third-party HTTP chatter out of the run log.
    for noisy in ("httpx", "httpcore", "trafilatura", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _parse_stages(stages: str | None) -> tuple[str, ...]:
    if not stages:
        return STAGES
    chosen = tuple(s.strip() for s in stages.split(",") if s.strip())
    unknown = [s for s in chosen if s not in STAGES]
    if unknown:
        raise typer.BadParameter(f"unknown stage(s): {', '.join(unknown)}; valid: {', '.join(STAGES)}")
    return tuple(s for s in STAGES if s in chosen)


@app.command()
def init() -> None:
    """Create the database and output directories."""
    root = repo_root()
    ctx = open_context(root)
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"database ready at {root / ctx.settings.db_path}")


@app.command()
def run(
    stages: str = typer.Option(None, help="Comma-separated subset of stages to run, in pipeline order."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM analysis and hunt drafting."),
    limit: int = typer.Option(None, help="Maximum documents each LLM stage takes this run."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run the pipeline (all stages by default)."""
    root = repo_root()
    _setup_logging(root, verbose)
    ctx = open_context(root, llm_enabled=not no_llm)
    ctx.llm_limit = limit
    result = run_pipeline(ctx, _parse_stages(stages))
    _print_run(result)
    if result["status"] in {"partial", "failed"}:
        raise typer.Exit(1)


@app.command()
def submit(
    url: str,
    analyse: bool = typer.Option(True, help="Run the remaining stages for the submitted report."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Manually submit a report URL, then process it through the pipeline."""
    from tipipeline.collect import submit_url

    root = repo_root()
    _setup_logging(root, verbose)
    ctx = open_context(root)
    with run_lock(ctx.data_dir):
        document_id = submit_url(ctx, url)
    console.print(f"stored as document {document_id}")
    if analyse:
        result = run_pipeline(ctx, tuple(s for s in STAGES if s != "collect"))
        _print_run(result)
        if result["status"] in {"partial", "failed"}:
            raise typer.Exit(1)


@app.command()
def investigate(
    value: str = typer.Argument(..., help="Report URL, CVE, ATT&CK technique ID or hypothesis."),
    kind: str = typer.Option("auto", help="auto, url, cve, technique or hypothesis."),
    customer: str = typer.Option(None, help="Customer profile ID to steer drafting; general investigation when omitted."),
    include_scraped: bool = typer.Option(False, "--include-scraped", help="Also use indicators scraped from article text."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Investigate a URL, CVE, technique or hypothesis now and print the result page path."""
    from tipipeline.dashboard.investigations import write_investigation_page
    from tipipeline.investigate import create_investigation, run_investigation

    root = repo_root()
    _setup_logging(root, verbose)
    ctx = open_context(root)
    try:
        investigation_id = create_investigation(
            ctx, value, kind=kind, profile_id=customer,
            include_scraped=include_scraped or ctx.settings.hunt.include_scraped_iocs,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    investigation = run_investigation(ctx, investigation_id)
    console.print(f"investigation {investigation_id}: {investigation.status}")
    if investigation.error:
        console.print(investigation.error)
    console.print(str(write_investigation_page(ctx, investigation_id)))
    if investigation.status == "error":
        raise typer.Exit(1)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Address to listen on, e.g. this machine's tailnet address."),
    port: int = typer.Option(8765),
    hostname: list[str] = typer.Option(None, "--hostname", help="Trusted hostname alias; repeat for each MagicDNS name."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Serve the dashboard and run investigations submitted from it, one at a time."""
    from tipipeline.serve import serve as run_server

    root = repo_root()
    _setup_logging(root, verbose)
    run_server(root, host, port, hostnames=tuple(hostname or ()))


@app.command()
def stage(name: str, verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    """Run a single stage (useful while developing)."""
    root = repo_root()
    _setup_logging(root, verbose)
    ctx = open_context(root)
    with run_lock(ctx.data_dir):
        result = run_stage(ctx, name)
        console.print_json(json.dumps(result))
    if result["status"] in {"error", "partial", "failed"}:
        raise typer.Exit(1)


@app.command()
def status() -> None:
    """Show collection and analysis counts plus the last run."""
    ctx = open_context(repo_root())
    db = ctx.db
    counts = {
        "documents": "SELECT COUNT(*) FROM documents",
        "duplicates": "SELECT COUNT(*) FROM documents WHERE duplicate_of IS NOT NULL",
        "indicators": "SELECT COUNT(*) FROM indicators",
        "analysed": "SELECT COUNT(*) FROM analyses WHERE status = 'ok'",
        "hunts prepared": "SELECT COUNT(*) FROM hunts WHERE status = 'prepared'",
        "queries": "SELECT COUNT(*) FROM queries",
    }
    table = Table(title="ti-pipeline")
    table.add_column("metric")
    table.add_column("value", justify="right")
    for label, sql in counts.items():
        table.add_row(label, str(db.execute(sql).fetchone()[0]))
    last = db.execute("SELECT id, started_at, status FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    if last:
        table.add_row("last run", f"#{last['id']} {last['started_at']} {last['status']}")
    console.print(table)


def _print_run(result: dict) -> None:
    table = Table(title=f"run #{result['run_id']}: {result['status']}")
    table.add_column("stage")
    table.add_column("status")
    table.add_column("seconds", justify="right")
    table.add_column("details")
    for name, stats in result["stages"].items():
        details = {k: v for k, v in stats.items() if k not in {"status", "seconds"}}
        table.add_row(name, stats["status"], str(stats.get("seconds", "")), json.dumps(details)[:120])
    console.print(table)


if __name__ == "__main__":
    app()
