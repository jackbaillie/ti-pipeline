"""Markdown intelligence briefs, PEAK hunt packages and per-profile digests."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml

from tipipeline.report.data import snapshot_from_context
from tipipeline.report.digest import build_profile_digest, digest_window
from tipipeline.report.markdown import digest_markdown, document_markdown, hunt_markdown
from tipipeline.report.text import defang


class _HuntDumper(yaml.SafeDumper):
    pass


def _literal_string(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)


_HuntDumper.add_representer(str, _literal_string)


def write_tree(directory: Path, files: dict[str, str], *, suffixes: tuple[str, ...]) -> None:
    """Replace a stage-owned output tree, removing stale generated files on reruns.

    Digest history is handled as individual dated directories, so old digests
    are retained. No files outside the stage-owned trees are touched.
    """
    directory.mkdir(parents=True, exist_ok=True)
    expected = {directory / name for name in files}
    for old in directory.rglob("*"):
        if old.is_file() and old.suffix in suffixes and old not in expected:
            old.unlink()
    for name, content in files.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def generate(ctx, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    s = snapshot_from_context(ctx, now)
    window = digest_window(ctx.db, ctx.run_id, now, s.tz)
    reports = ctx.output_dir / "reports"
    docs = {f"{id_}.md": document_markdown(s, s.docs[id_]) for id_ in s.assessed_doc_ids()}
    write_tree(reports / "documents", docs, suffixes=(".md",))
    hunt_files = {}
    for h in s.hunts.values():
        stem = f"{h.profile_id}/{h.stem}"
        hunt_files[stem + ".md"] = hunt_markdown(s, h)
        package = h.package.model_dump() if h.package else {
            "document_id": h.document_id, "profile_id": h.profile_id, "title": h.title,
            "status": h.status, "package_error": h.package_error,
        }
        package["queries"] = [q.as_dict() for q in h.queries]
        hunt_files[stem + ".yaml"] = yaml.dump(package, Dumper=_HuntDumper, allow_unicode=True, sort_keys=False)
    write_tree(ctx.output_dir / "hunts", hunt_files, suffixes=(".md", ".yaml"))
    upload_dir = ctx.output_dir / "stix" / "sentinel-upload"
    uploads = sorted(p for p in upload_dir.glob("*") if p.is_file())
    dated, latest = {}, {}
    for profile in ctx.profiles:
        digest = build_profile_digest(s, profile.id, window)
        dated[f"{profile.id}.md"] = digest_markdown(s, digest, reports_prefix="../../documents/", hunts_prefix="../../../hunts/", stix_prefix="../../../stix/sentinel-upload/", upload_files=uploads)
        latest[f"{profile.id}.md"] = digest_markdown(s, digest, reports_prefix="../documents/", hunts_prefix="../../hunts/", stix_prefix="../../stix/sentinel-upload/", upload_files=uploads)
    write_tree(reports / "digests" / window.label, dated, suffixes=(".md",))
    write_tree(reports / "latest", latest, suffixes=(".md",))
    ctx.log.info("Rendered %d document briefs, %d hunts and %d digests", len(docs), len(s.hunts), len(dated))
    return {"documents": len(docs), "hunts": len(s.hunts), "digests": len(dated), "digest_window_start": window.start.isoformat(), "digest_label": window.label}


def run(ctx) -> dict:
    return generate(ctx)


__all__ = ["run", "generate", "defang"]
