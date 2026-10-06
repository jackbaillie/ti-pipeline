"""Stories: connected components of evidence links, not campaign attribution.

``documents.cluster_id`` is the story key. Documents join a story when they
share an unflagged indicator or CVE, are near-duplicates, or are CISA KEV
entries for the same vendor and product added within 30 days of each other
(those KEV joins are computed here and not stored as links).

Values mentioned by more than eight non-duplicate documents are ignored:
common infrastructure or ubiquitous CVEs must not collapse the corpus into
one giant component. Round-ups (weekly digests and newsletters covering
unrelated items) and patch bulletins keep their link rows, so related views
can list them, but never join a story: otherwise one digest would bridge
every item it mentions. Existing near-duplicate links remain process-owned.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import date
from itertools import combinations, pairwise

from tipipeline.relevance.rules import is_patch_bulletin

MAX_DOCS_PER_SHARED_VALUE = 8
KEV_SAME_PRODUCT_DAYS = 30
# Analyses stored before "roundup" existed typed digests as "news", and some
# digests are not analysed yet. These titles and openings mark them:
# "5th October – Threat Intelligence Report", "The Week in Ransomware",
# "This month in security", "Welcome to this week's edition of the ... newsletter".
ROUNDUP_TITLE = re.compile(
    r"^\d{1,2}(?:st|nd|rd|th)? \w+ [–-] threat intelligence report$"
    r"|\b(?:week|month) in (?:review|security|ransomware)\b|\bweekly (?:recap|round-?up|digest)\b", re.I)
ROUNDUP_OPENING = re.compile(r"\bweek['’]s edition of\b", re.I)


def is_roundup(title: str, report_type: str | None, opening: str = "") -> bool:
    if report_type == "roundup": return True
    return report_type in (None, "news") and bool(ROUNDUP_TITLE.search(title) or ROUNDUP_OPENING.search(opening))


def _non_bridging(db: sqlite3.Connection) -> set[int]:
    """Round-ups and patch bulletins: documents that cover many unrelated items."""
    cves: dict[int, set[str]] = defaultdict(set)
    for document_id, value in db.execute("""SELECT di.document_id,i.value FROM document_indicators di
            JOIN indicators i ON i.id=di.indicator_id WHERE i.type='cve'"""):
        cves[document_id].add(value)
    found = set()
    for document_id, title, opening, report_type, analysis_json in db.execute("""
            SELECT d.id,d.title,substr(d.text,1,300),a.report_type,a.analysis_json FROM documents d
            LEFT JOIN analyses a ON a.document_id=d.id"""):
        if is_roundup(title, report_type, opening):
            found.add(document_id)
        elif report_type == "vulnerability":
            listed = (json.loads(analysis_json) if analysis_json else {}).get("cves") or []
            if is_patch_bulletin(title, report_type, cves[document_id] | {str(cve).strip().upper() for cve in listed}):
                found.add(document_id)
    return found


def _kev_pairs(documents) -> list[tuple[int, int]]:
    """Consecutive KEV entries for one vendor/product added within the window."""
    entries: dict[tuple[str, str], list[tuple[date, int]]] = defaultdict(list)
    for document in documents:
        if document["kind"] != "vulnerability" or document["duplicate_of"] is not None: continue
        metadata = json.loads(document["meta_json"] or "{}")
        vendor, product = (str(metadata.get(key) or "").strip().lower() for key in ("vendorProject", "product"))
        try: added = date.fromisoformat(str(metadata.get("dateAdded")))
        except ValueError: continue
        if vendor and product: entries[vendor, product].append((added, document["id"]))
    return [(a, b) for group in entries.values()
            for (first, a), (second, b) in pairwise(sorted(group)) if (second - first).days <= KEV_SAME_PRODUCT_DAYS]


def _shared_values(db: sqlite3.Connection) -> dict[tuple[str, str], set[int]]:
    shared: dict[tuple[str, str], set[int]] = defaultdict(set)
    for row in db.execute("""SELECT di.document_id,i.type,i.value FROM document_indicators di
        JOIN indicators i ON i.id=di.indicator_id JOIN documents d ON d.id=di.document_id
        WHERE d.duplicate_of IS NULL AND di.warninglist IS NULL"""):
        shared[row["type"], row["value"]].add(row["document_id"])
    return shared


def run(ctx) -> dict:
    documents = ctx.db.execute("SELECT id,kind,meta_json,duplicate_of FROM documents ORDER BY id").fetchall()
    parents = {doc["id"]: doc["id"] for doc in documents}

    def find(value: int) -> int:
        while parents[value] != value:
            parents[value] = parents[parents[value]]
            value = parents[value]
        return value

    def union(a: int, b: int) -> None:
        if a not in parents or b not in parents: return
        a, b = find(a), find(b)
        if a != b: parents[max(a, b)] = min(a, b)

    links: dict[tuple[int, int, str], list[str]] = defaultdict(list)
    ignored = 0
    for (type_, value), document_ids in sorted(_shared_values(ctx.db).items()):
        if len(document_ids) > MAX_DOCS_PER_SHARED_VALUE:
            ignored += 1
            continue
        reason = "shared_cve" if type_ == "cve" else "shared_indicator"
        for a, b in combinations(sorted(document_ids), 2): links[a, b, reason].append(value)
    ctx.db.execute("DELETE FROM document_links WHERE reason IN ('shared_indicator','shared_cve')")
    for (a, b, reason), values in links.items():
        detail = ", ".join(values[:5]) + (f" (+{len(values)-5} more)" if len(values) > 5 else "")
        ctx.db.execute("INSERT INTO document_links (doc_a,doc_b,reason,detail,score) VALUES (?,?,?,?,?)",
                       (a, b, reason, detail, len(values)))
    apart = _non_bridging(ctx.db)
    for a, b in ctx.db.execute("SELECT doc_a,doc_b FROM document_links"):
        if a not in apart and b not in apart: union(a, b)
    kev_pairs = _kev_pairs(documents)
    for a, b in kev_pairs: union(a, b)
    # A duplicate is the same document, so it always shares its original's story.
    for document in documents:
        if document["duplicate_of"] is not None: union(document["id"], document["duplicate_of"])
    for document in documents:
        ctx.db.execute("UPDATE documents SET cluster_id=? WHERE id=?", (find(document["id"]), document["id"]))
    ctx.db.commit()
    sizes = Counter(find(document["id"]) for document in documents)
    story_sizes = Counter(find(document["id"]) for document in documents if document["duplicate_of"] is None)
    return {"documents": len(documents), "clusters": len(sizes), "singletons": sum(size == 1 for size in sizes.values()),
            "cluster_sizes": sorted(sizes.values(), reverse=True), "ignored_common_indicators": ignored,
            "links_by_reason": dict(Counter(key[2] for key in links)),
            "multi_document_stories": sum(size > 1 for size in story_sizes.values()),
            "largest_story": max(story_sizes.values(), default=0),
            "kept_apart": len(apart), "kev_same_product_joins": len(kev_pairs)}


def story_members(conn: sqlite3.Connection, document_id: int) -> list[int]:
    """Document ids in a document's story, read-only.

    Uses the stored cluster_id when the cluster stage has run. A document not
    clustered yet gets the stories of documents it shares an unflagged value
    with (same common-value cut-off; round-ups and bulletins do not bridge),
    plus itself."""
    row = conn.execute("SELECT cluster_id,duplicate_of FROM documents WHERE id=?", (document_id,)).fetchone()
    if row is None: return []
    if row[0] is not None:
        return [r[0] for r in conn.execute("SELECT id FROM documents WHERE cluster_id=? ORDER BY id", (row[0],))]
    if row[1] is not None: return sorted({document_id, *story_members(conn, row[1])})
    apart = _non_bridging(conn)
    if document_id in apart: return [document_id]
    members = {document_id}
    for (indicator_id,) in conn.execute("""SELECT indicator_id FROM document_indicators
            WHERE document_id=? AND warninglist IS NULL""", (document_id,)).fetchall():
        others = {r[0] for r in conn.execute("""SELECT di.document_id FROM document_indicators di
            JOIN documents d ON d.id=di.document_id
            WHERE di.indicator_id=? AND di.warninglist IS NULL AND d.duplicate_of IS NULL""", (indicator_id,))}
        if len(others | {document_id}) > MAX_DOCS_PER_SHARED_VALUE: continue
        for partner in others - apart - {document_id}:
            cluster_id = conn.execute("SELECT cluster_id FROM documents WHERE id=?", (partner,)).fetchone()[0]
            if cluster_id is None: members.add(partner)
            else: members.update(r[0] for r in conn.execute("SELECT id FROM documents WHERE cluster_id=?", (cluster_id,)))
    return sorted(members)
