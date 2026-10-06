"""Manual investigations: look one thing up across collected reporting and draft a hunt for it.

An investigation takes a report URL, a CVE, an ATT&CK technique ID or a
free-text hypothesis. It gathers the matching reports (grouped by story),
their indicators, CVEs and techniques, then asks the hunt drafter for a
hypothesis and schema-checked KQL. Nothing runs against a workspace.

Investigations are rows in the ``investigations`` table. ``ti-pipeline
investigate`` runs one synchronously; ``ti-pipeline serve`` queues them from the
dashboard form and runs them one at a time.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from types import SimpleNamespace

from tipipeline import analyse, cluster, collect, extract
from tipipeline.analyse import document_date
from tipipeline.db import dumps, now_iso
from tipipeline.hunt.draft import DraftResult, ReportInput, draft_hunt
from tipipeline.models import AnalysisValidation, InvestigationTerms, ReportAnalysis
from tipipeline.pipeline import Context, _flush_llm_calls, run_lock
from tipipeline.report.markdown import kev_fields
from tipipeline.report.text import defang

KINDS = ("url", "cve", "technique", "hypothesis")
KIND_LABELS = {
    "auto": "Detect automatically",
    "url": "Report URL",
    "cve": "CVE",
    "technique": "ATT&CK technique",
    "hypothesis": "Hypothesis",
}
MAX_INPUT_LENGTH = 2000
# Hypothesis search keeps the best ten; exact CVE/technique lookups retain all matches.
SEARCH_LIMIT = 10
# Hypothesis search: points per term hit.
TITLE_POINTS, TEXT_POINTS, ID_POINTS = 3, 1, 3
MAX_TERMS = 8

_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
_CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_TECHNIQUE_IN_TEXT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

TERMS_PROMPT = """Turn an analyst's threat-hunting hypothesis into search terms for a database of \
collected threat-intelligence reports. Matching is case-insensitive substring search on report \
titles and text, so prefer short, distinctive terms that reporting would use.

- keywords: threat actors, malware families, tools and behaviours; at most {limit}, one to three words each.
- products: vendor or product names as reporting writes them, e.g. "NetScaler", "FortiOS"; at most 5.
- technique_ids: ATT&CK Enterprise technique IDs the hypothesis describes; at most 5.
- cves: CVE IDs written in the hypothesis; empty if none.

Hypothesis:
<<<
{hypothesis}
>>>"""


@dataclass
class Investigation:
    id: int
    created_at: str
    updated_at: str
    kind: str
    input: str
    profile_id: str | None
    include_scraped: bool
    status: str
    result: dict | None
    error: str | None

    @property
    def active(self) -> bool:
        return self.status in {"queued", "running"}


@dataclass
class _Found:
    """What a lookup matched: report id -> reasons, in rank order."""

    focus: str
    empty: str
    matches: dict[int, list[str]] = field(default_factory=dict)
    kev: dict | None = None
    terms: dict | None = None
    notes: list[str] = field(default_factory=list)
    # URL investigations group the submitted report and its story as one story.
    one_story: bool = False
    document_id: int | None = None


# --------------------------------------------------------------------------
# Input and storage
# --------------------------------------------------------------------------


def detect_kind(value: str) -> str:
    value = value.strip()
    if _URL.fullmatch(value):
        return "url"
    if _CVE.fullmatch(value):
        return "cve"
    if _TECHNIQUE.fullmatch(value):
        return "technique"
    return "hypothesis"


def resolve_input(value: str, kind: str = "auto") -> tuple[str, str]:
    """Validate the input and return ``(kind, normalised value)``; raises ValueError with a readable message."""
    value = value.strip()
    if not value:
        raise ValueError("Enter a report URL, a CVE, an ATT&CK technique ID or a hypothesis.")
    if len(value) > MAX_INPUT_LENGTH:
        raise ValueError(f"Keep the input to {MAX_INPUT_LENGTH:,} characters or fewer.")
    if kind == "auto":
        kind = detect_kind(value)
    if kind not in KINDS:
        raise ValueError(f"Unknown investigation type: {kind}.")
    if kind == "url" and not _URL.fullmatch(value):
        raise ValueError("A report URL starts with http:// or https:// and has no spaces.")
    if kind == "cve":
        if not _CVE.fullmatch(value):
            raise ValueError("A CVE looks like CVE-2025-5777.")
        value = value.upper()
    if kind == "technique":
        if not _TECHNIQUE.fullmatch(value):
            raise ValueError("An ATT&CK technique ID looks like T1133 or T1059.001.")
        value = value.upper()
    return kind, value


def create_investigation(
    ctx: Context, value: str, *, kind: str = "auto", profile_id: str | None = None, include_scraped: bool = False
) -> int:
    """Validate and queue an investigation; returns its id."""
    kind, value = resolve_input(value, kind)
    if profile_id and profile_id not in {p.id for p in ctx.profiles}:
        raise ValueError(f"Unknown customer: {profile_id}.")
    stamp = now_iso()
    cur = ctx.db.execute(
        """INSERT INTO investigations (created_at, updated_at, kind, input, profile_id, include_scraped)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (stamp, stamp, kind, value, profile_id or None, int(include_scraped)),
    )
    ctx.db.commit()
    return int(cur.lastrowid)


def _investigation(row: sqlite3.Row) -> Investigation:
    return Investigation(
        id=row["id"], created_at=row["created_at"], updated_at=row["updated_at"], kind=row["kind"],
        input=row["input"], profile_id=row["profile_id"], include_scraped=bool(row["include_scraped"]),
        status=row["status"], result=json.loads(row["result_json"]) if row["result_json"] else None,
        error=row["error"],
    )


def get_investigation(conn: sqlite3.Connection, investigation_id: int) -> Investigation | None:
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    return _investigation(row) if row else None


def list_investigations(conn: sqlite3.Connection, limit: int | None = None) -> list[Investigation]:
    """Newest first."""
    sql = "SELECT * FROM investigations ORDER BY id DESC"
    rows = conn.execute(sql + " LIMIT ?", (limit,)) if limit is not None else conn.execute(sql)
    return [_investigation(row) for row in rows]


def recover_interrupted(conn: sqlite3.Connection) -> list[int]:
    """After a server restart: fail investigations that were mid-run and return the queued ids to resume."""
    conn.execute(
        "UPDATE investigations SET status = 'error', error = ?, updated_at = ? WHERE status = 'running'",
        ("Interrupted: the server stopped before this investigation finished. Run it again.", now_iso()),
    )
    conn.commit()
    return [row[0] for row in conn.execute("SELECT id FROM investigations WHERE status = 'queued' ORDER BY id")]


def _finish(conn: sqlite3.Connection, investigation_id: int, status: str, result: dict | None, error: str | None) -> None:
    conn.execute(
        "UPDATE investigations SET status = ?, result_json = ?, error = ?, updated_at = ? WHERE id = ?",
        (status, dumps(result) if result is not None else None, error, now_iso(), investigation_id),
    )
    conn.commit()


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------


def run_investigation(ctx: Context, investigation_id: int) -> Investigation:
    """Run one investigation and store its result. Failures are recorded on the row, not raised."""
    investigation = get_investigation(ctx.db, investigation_id)
    if investigation is None:
        raise LookupError(f"investigation {investigation_id} does not exist")
    ctx.db.execute(
        "UPDATE investigations SET status = 'running', error = NULL, updated_at = ? WHERE id = ?",
        (now_iso(), investigation_id),
    )
    ctx.db.commit()
    result = error = None
    try:
        result = _investigate(ctx, investigation)
    except Exception as exc:  # recorded on the row; the server keeps running
        ctx.db.rollback()
        error = f"{type(exc).__name__}: {exc}"[:2000]
        ctx.log.warning("investigation %s failed: %s", investigation_id, error)
    finally:
        _flush_llm_calls(ctx)
    _finish(ctx.db, investigation_id, "error" if error else "done", result, error)
    return get_investigation(ctx.db, investigation_id)


def _analyse_matches(ctx: Context, found: _Found) -> None:
    """Refresh at most ten retrieved article/advisory analyses, in retrieval order."""
    for document_id in list(found.matches)[:10]:
        row = ctx.db.execute(
            """SELECT d.kind, d.title, d.version, a.status, a.document_version
               FROM documents d LEFT JOIN analyses a ON a.document_id=d.id WHERE d.id=?""",
            (document_id,),
        ).fetchone()
        if row is None or row["kind"] not in {"article", "advisory"}:
            continue
        if row["status"] == "ok" and row["document_version"] == row["version"]:
            continue
        try:
            analyse.analyse_document(ctx, document_id)
        except Exception as exc:
            found.notes.append(f"Report analysis failed for {row['title']}: {exc}")


def _investigate(ctx: Context, investigation: Investigation) -> dict:
    lookups = {"url": _url_lookup, "cve": _cve_lookup, "technique": _technique_lookup, "hypothesis": _hypothesis_lookup}
    if investigation.kind == "url":
        _finish(ctx.db, investigation.id, "running", {
            "notes": [], "empty": "Waiting for the pipeline lock before fetching the submitted report.", "hunt": None,
        }, None)
        with run_lock(ctx.data_dir, blocking=True):
            _finish(ctx.db, investigation.id, "running", {
                "notes": [], "empty": "Fetching, extracting and analysing the submitted report.", "hunt": None,
            }, None)
            found = _url_lookup(ctx, investigation.input)
    else:
        found = lookups[investigation.kind](ctx, investigation.input)
        _analyse_matches(ctx, found)
    evidence = _compile(ctx, found, include_scraped=investigation.include_scraped)
    result = {
        "focus": found.focus, "terms": found.terms, "kev": found.kev, "notes": found.notes,
        "empty": None, "hunt": None, "hunt_error": None, **evidence,
    }
    if not evidence["stories"] and not found.kev:
        result["empty"] = found.empty
        return result
    reports = _draft_reports(ctx, evidence)
    omitted = evidence["report_count"] - len(reports)
    if omitted:
        result["notes"].append(
            f"{omitted} additional matches did not inform the hunt because they have no current successful analysis. "
            "On-demand analysis is limited to the first 10 retrieved matches."
        )
    if not reports:
        result["hunt_error"] = "No source-supported hunt could be drafted: no matched report has a current successful analysis."
        return result
    profile = next((p for p in ctx.profiles if p.id == investigation.profile_id), None)
    indicators = [{"type": i["type"], "value": i["value"], "context": i["contexts"][0]} for i in evidence["iocs"]]
    try:
        draft = draft_hunt(
            ctx, focus=found.focus, reports=reports, indicators=indicators,
            profile=profile, document_id=found.document_id,
        )
    except Exception as exc:  # the evidence still stands without a draft
        result["hunt_error"] = f"{type(exc).__name__}: {exc}"[:2000]
        ctx.log.warning("investigation %s: hunt drafting failed: %s", investigation.id, result["hunt_error"])
    else:
        if draft.queries:
            result["hunt"] = _draft_record(draft)
            result["hunt"]["sources"] = [
                {"id": report.document["id"], "title": report.document["title"]} for report in reports
            ]
        else:
            result["hunt_error"] = "No source-supported hunt could be drafted: no queries passed the schema check."
    return result


# --------------------------------------------------------------------------
# Lookups
# --------------------------------------------------------------------------


def _by_recency(conn: sqlite3.Connection, ids) -> list[int]:
    """The given documents newest first, without near-duplicates (their original stands for them)."""
    ids = sorted(set(ids))
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT id, published_at, collected_at FROM documents WHERE id IN ({marks}) AND duplicate_of IS NULL", ids
    )
    return [row["id"] for row in sorted(rows, key=lambda r: (document_date(dict(r)), r["id"]), reverse=True)]


def _url_lookup(ctx: Context, url: str) -> _Found:
    document_id = collect.submit_url(ctx, url)
    extract.extract_document(ctx, document_id)
    document = ctx.db.execute(
        """SELECT d.title, d.version, a.status, a.document_version FROM documents d
           LEFT JOIN analyses a ON a.document_id = d.id WHERE d.id = ?""",
        (document_id,),
    ).fetchone()
    found = _Found(
        focus=f"Submitted report: {document['title']} ({url}). Hunt for the activity it describes.",
        empty="",
        one_story=True,
        document_id=document_id,
    )
    if document["status"] != "ok" or document["document_version"] != document["version"]:
        try:
            analyse.analyse_document(ctx, document_id)
        except Exception as exc:  # stored as an analysis error; evidence is still useful
            found.notes.append(f"Report analysis failed, so the draft has no attack steps from this report: {exc}")
    others = [i for i in cluster.story_members(ctx.db, document_id) if i != document_id]
    found.matches = {document_id: ["submitted report"]}
    found.matches.update((i, ["same story"]) for i in _by_recency(ctx.db, others))
    return found


def _kev_entry(conn: sqlite3.Connection, cve: str) -> dict | None:
    row = conn.execute(
        """SELECT id, title, url, meta_json FROM documents
           WHERE kind = 'vulnerability' AND json_extract(meta_json, '$.cveID') = ? ORDER BY id DESC""",
        (cve,),
    ).fetchone()
    if row is None:
        return None
    meta = json.loads(row["meta_json"])
    return {
        "document_id": row["id"], "title": row["title"], "url": row["url"],
        "product": " ".join(v for v in (meta.get("vendorProject"), meta.get("product")) if v),
        "name": meta.get("vulnerabilityName") or row["title"],
        "description": meta.get("shortDescription", ""),
        "ransomware": meta.get("knownRansomwareCampaignUse", ""),
        "fields": [list(pair) for pair in kev_fields(SimpleNamespace(meta=meta))],
    }


def _cve_lookup(ctx: Context, cve: str) -> _Found:
    kev = _kev_entry(ctx.db, cve)
    rows = ctx.db.execute(
        """SELECT DISTINCT di.document_id FROM document_indicators di
           JOIN indicators i ON i.id = di.indicator_id JOIN documents d ON d.id = di.document_id
           WHERE i.type = 'cve' AND i.value = ? AND d.duplicate_of IS NULL AND d.kind != 'vulnerability'""",
        (cve,),
    )
    ranked = _by_recency(ctx.db, (row[0] for row in rows))
    focus = f"Exploitation of {cve}."
    if kev:
        focus += f" CISA lists it as known exploited: {kev['product']}, {kev['name']}."
        if kev["description"]:
            focus += f" {kev['description']}"
        if kev["ransomware"].casefold() == "known":
            focus += " CISA records known ransomware campaign use."
    focus += " Hunt for signs of exploitation and the follow-on activity the reports describe."
    found = _Found(focus=focus, empty=f"No collected reports mention {cve}, and it is not in the collected CISA KEV entries.", kev=kev)
    found.matches = {doc_id: [f"mentions {cve}"] for doc_id in ranked}
    return found


def _technique_lookup(ctx: Context, technique_id: str) -> _Found:
    parent = "." not in technique_id
    rows = ctx.db.execute(
        """SELECT DISTINCT dt.document_id, dt.technique_id FROM document_techniques dt
           JOIN documents d ON d.id = dt.document_id
           WHERE dt.valid = 1 AND d.duplicate_of IS NULL
             AND (dt.technique_id = ? OR (? AND dt.technique_id LIKE ?))
           ORDER BY dt.technique_id""",
        (technique_id, int(parent), f"{technique_id}.%"),
    ).fetchall()
    reasons: dict[int, list[str]] = defaultdict(list)
    for row in rows:
        reasons[row["document_id"]].append(row["technique_id"])
    known = ctx.attack.get(technique_id)
    label = f"{technique_id} {known.name}" if known else technique_id
    scope = " and its sub-techniques" if parent else ""
    found = _Found(
        focus=f"ATT&CK {label}{scope}. Hunt for this technique as the reports describe it.",
        empty=f"No collected reports map to {technique_id}{scope}.",
    )
    if known is None:
        found.notes.append(f"{technique_id} is not in the current ATT&CK catalogue.")
    found.matches = {doc_id: reasons[doc_id] for doc_id in _by_recency(ctx.db, reasons)}
    return found


def extract_terms(ctx: Context, hypothesis: str) -> InvestigationTerms:
    """One model call turns the hypothesis into search terms; IDs written in the text always count."""
    terms = ctx.llm.complete(
        task="investigation_terms", prompt=TERMS_PROMPT.format(limit=MAX_TERMS, hypothesis=hypothesis),
        schema=InvestigationTerms, effort=ctx.effort("investigation_terms"),
    )
    cves = {c.strip().upper() for c in [*terms.cves, *_CVE_IN_TEXT.findall(hypothesis)] if _CVE.fullmatch(c.strip())}
    techniques = {
        t.strip().upper() for t in [*terms.technique_ids, *_TECHNIQUE_IN_TEXT.findall(hypothesis)]
        if _TECHNIQUE.fullmatch(t.strip()) and ctx.attack.is_valid(t.strip())
    }
    return InvestigationTerms(
        keywords=_clean_terms(terms.keywords), products=_clean_terms(terms.products),
        technique_ids=sorted(techniques), cves=sorted(cves),
    )


def _clean_terms(values: list[str]) -> list[str]:
    seen, kept = set(), []
    for value in values:
        value = " ".join(value.split())
        if 3 <= len(value) <= 60 and value.casefold() not in seen:
            seen.add(value.casefold())
            kept.append(value)
    return kept[:MAX_TERMS]


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def search_reports(conn: sqlite3.Connection, terms: InvestigationTerms, limit: int = SEARCH_LIMIT) -> dict[int, list[str]]:
    """Rank non-duplicate reports by term hits (title over text), then recency; returns id -> reasons."""
    scores: dict[int, int] = defaultdict(int)
    reasons: dict[int, list[str]] = defaultdict(list)
    for term in [*terms.keywords, *terms.products]:
        pattern = _like(term)
        for row in conn.execute(
            r"""SELECT id, title LIKE ? ESCAPE '\' AS in_title FROM documents
                WHERE duplicate_of IS NULL AND (title LIKE ? ESCAPE '\' OR text LIKE ? ESCAPE '\')""",
            (pattern, pattern, pattern),
        ):
            scores[row["id"]] += TITLE_POINTS if row["in_title"] else TEXT_POINTS
            reasons[row["id"]].append(f"{term} ({'title' if row['in_title'] else 'text'})")
    for technique_id in terms.technique_ids:
        for row in conn.execute(
            """SELECT DISTINCT dt.document_id FROM document_techniques dt JOIN documents d ON d.id = dt.document_id
               WHERE dt.valid = 1 AND d.duplicate_of IS NULL AND (dt.technique_id = ? OR dt.technique_id LIKE ?)""",
            (technique_id, f"{technique_id}.%"),
        ):
            scores[row[0]] += ID_POINTS
            reasons[row[0]].append(technique_id)
    for cve in terms.cves:
        for row in conn.execute(
            """SELECT DISTINCT di.document_id FROM document_indicators di JOIN indicators i ON i.id = di.indicator_id
               JOIN documents d ON d.id = di.document_id
               WHERE i.type = 'cve' AND i.value = ? AND d.duplicate_of IS NULL""",
            (cve,),
        ):
            scores[row[0]] += ID_POINTS
            reasons[row[0]].append(cve)
    recency = {doc_id: rank for rank, doc_id in enumerate(_by_recency(conn, scores))}
    ranked = sorted(scores, key=lambda doc_id: (-scores[doc_id], recency[doc_id]))
    return {doc_id: reasons[doc_id] for doc_id in ranked[:limit]}


def _hypothesis_lookup(ctx: Context, hypothesis: str) -> _Found:
    terms = extract_terms(ctx, hypothesis)
    found = _Found(
        focus=f"Analyst hypothesis: {hypothesis}",
        empty="No collected reports match the search terms drawn from this hypothesis.",
        terms=terms.model_dump(),
    )
    found.matches = search_reports(ctx.db, terms)
    return found


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


def _report_ids(evidence: dict) -> list[int]:
    return [report["id"] for story in evidence["stories"] for report in story["reports"]]


def _compile(ctx: Context, found: _Found, *, include_scraped: bool) -> dict:
    """Group matched reports by story and collect their IOCs, CVEs and techniques."""
    ids = list(found.matches)
    if not ids:
        return {"stories": [], "report_count": 0, "iocs": [], "iocs_benign": 0, "iocs_scraped_hidden": 0,
                "cves": [], "techniques": []}
    marks = ",".join("?" * len(ids))
    source_names = {s.id: s.name for s in ctx.sources}
    documents = {
        row["id"]: row for row in ctx.db.execute(
            f"""SELECT d.id, d.title, d.url, d.source_id, d.kind, d.published_at, d.collected_at, d.cluster_id,
                       d.duplicate_of, a.status AS analysis_status, a.summary, a.report_type
                FROM documents d LEFT JOIN analyses a ON a.document_id = d.id AND a.document_version = d.version
                WHERE d.id IN ({marks})""",
            ids,
        )
    }
    stories: dict[int, dict] = {}
    for doc_id, reasons in found.matches.items():
        row = documents.get(doc_id)
        if row is None:
            continue
        key = ids[0] if found.one_story else (row["cluster_id"] if row["cluster_id"] is not None else row["duplicate_of"] or doc_id)
        stories.setdefault(key, {"id": key, "reports": []})["reports"].append({
            "id": doc_id, "title": row["title"], "url": row["url"], "kind": row["kind"],
            "source": source_names.get(row["source_id"], "Manual submission" if row["source_id"] == "manual" else row["source_id"]),
            "date": row["published_at"] or row["collected_at"],
            "summary": row["summary"] if row["analysis_status"] == "ok" else "",
            "report_type": row["report_type"] if row["analysis_status"] == "ok" else None,
            "reasons": reasons,
        })

    # An IOC qualifies from an IOC section or feed when nothing flags it as benign
    # (warninglist, allowlist or the publisher's own domain). Article body text
    # counts only when the operator asks for scraped indicators.
    contexts = {"ioc_section", "feed"} | ({"body"} if include_scraped else set())
    iocs: dict[tuple[str, str], dict] = {}
    benign, scraped = set(), set()
    for row in ctx.db.execute(
        f"""SELECT i.type, i.value, di.document_id, di.context, di.warninglist FROM document_indicators di
            JOIN indicators i ON i.id = di.indicator_id
            WHERE di.document_id IN ({marks}) AND i.type != 'cve' ORDER BY i.type, i.value""",
        ids,
    ):
        key = (row["type"], row["value"])
        if row["warninglist"] is not None:
            benign.add(key)
            continue
        if row["context"] not in contexts:
            if row["context"] == "body":
                scraped.add(key)
            continue
        entry = iocs.setdefault(key, {"type": row["type"], "value": row["value"], "display": defang(*key),
                                      "contexts": [], "reports": []})
        if row["context"] not in entry["contexts"]:
            entry["contexts"].append(row["context"])
        if row["document_id"] not in entry["reports"]:
            entry["reports"].append(row["document_id"])

    cves = [
        {"id": row["value"], "reports": row["n"], "kev": bool(row["kev"])}
        for row in ctx.db.execute(
            f"""SELECT i.value, COUNT(DISTINCT di.document_id) AS n,
                       EXISTS (SELECT 1 FROM documents k WHERE k.kind = 'vulnerability'
                               AND json_extract(k.meta_json, '$.cveID') = i.value) AS kev
                FROM document_indicators di JOIN indicators i ON i.id = di.indicator_id
                WHERE di.document_id IN ({marks}) AND i.type = 'cve'
                GROUP BY i.value ORDER BY n DESC, i.value""",
            ids,
        )
    ]
    techniques = []
    for row in ctx.db.execute(
        f"""SELECT dt.technique_id, COUNT(DISTINCT dt.document_id) AS n FROM document_techniques dt
            JOIN documents d ON d.id=dt.document_id
            LEFT JOIN analyses a ON a.document_id=d.id AND a.document_version=d.version AND a.status='ok'
            WHERE dt.document_id IN ({marks}) AND dt.valid = 1
              AND (dt.source='explicit' OR a.document_id IS NOT NULL)
            GROUP BY dt.technique_id ORDER BY n DESC, dt.technique_id""",
        ids,
    ):
        known = ctx.attack.get(row["technique_id"])
        techniques.append({"id": row["technique_id"], "name": known.name if known else "", "reports": row["n"]})

    return {
        "stories": list(stories.values()),
        "report_count": sum(len(s["reports"]) for s in stories.values()),
        "iocs": list(iocs.values()),
        "iocs_benign": len(benign - set(iocs)),
        "iocs_scraped_hidden": len(scraped - set(iocs) - benign),
        "cves": cves,
        "techniques": techniques,
    }


def _draft_reports(ctx: Context, evidence: dict) -> list[ReportInput]:
    """Analysed reports for the drafter: every story's lead first, then the rest."""
    leads = [s["reports"][0]["id"] for s in evidence["stories"]]
    order = leads + [i for i in _report_ids(evidence) if i not in leads]
    rows = {
        row["id"]: row for row in ctx.db.execute(
            f"""SELECT d.id, d.title, d.url, d.source_id, d.published_at, a.analysis_json, a.validation_json
                FROM documents d JOIN analyses a ON a.document_id = d.id AND a.document_version = d.version
                WHERE a.status = 'ok' AND d.id IN ({','.join('?' * len(order))})""",
            order,
        )
    }
    reports = []
    for doc_id in order:
        row = rows.get(doc_id)
        if row is None:
            continue
        try:
            analysis = ReportAnalysis.model_validate_json(row["analysis_json"])
            validation = AnalysisValidation.model_validate_json(row["validation_json"]) if row["validation_json"] else None
        except ValueError as exc:
            ctx.log.warning("investigation: skipping document %s with an unreadable analysis: %s", doc_id, exc)
            continue
        document = {key: row[key] for key in ("id", "title", "url", "source_id", "published_at")}
        reports.append(ReportInput(document=document, analysis=analysis, validation=validation))
    return reports


def _draft_record(draft: DraftResult) -> dict:
    return {
        "title": draft.title,
        "hypothesis": draft.hypothesis,
        "scope": draft.scope,
        "pyramid_levels": list(draft.pyramid_levels),
        "techniques": [t.model_dump() for t in draft.techniques],
        "evidence": [e.model_dump() for e in draft.evidence],
        "gaps": list(draft.gaps),
        "dropped": draft.dropped,
        "queries": [
            {
                "id": f"q{index}", "kind": q.kind, "generated_by": q.generated_by, "title": q.query.title,
                "purpose": q.query.purpose, "kql": q.query.kql, "tables": list(q.query.tables),
                "technique_ids": list(q.query.technique_ids), "benign": list(q.query.benign_explanations),
                "pivots": list(q.query.pivots),
            }
            for index, q in enumerate(draft.queries, 1)
        ],
    }
