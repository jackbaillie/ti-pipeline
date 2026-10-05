"""Version-driven near-duplicate detection for articles and advisories.

Five-word shingle Jaccard >= 0.60 identifies substantially reproduced text;
0.40 <= Jaccard < 0.60 additionally requires >= 0.75 headline similarity.
That lower band catches edited syndication without merging independent coverage
of the same campaign. Common shingles (in >5 documents and >5% of the corpus)
are removed so recurring newsletter boilerplate does not dominate the score.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from difflib import SequenceMatcher

from tipipeline.db import dumps
from tipipeline.pipeline import Context


def _shingles(text: str) -> set[tuple[str, ...]]:
    words = re.findall(r"\w+", text.lower())
    return {tuple(words[i:i + 5]) for i in range(len(words) - 4)}


def _title(title: str) -> str:
    return " ".join(re.findall(r"\w+", title.lower()))


def run(ctx: Context) -> dict:
    pending = list(ctx.db.execute("SELECT * FROM documents WHERE processed_version IS NULL OR processed_version < version"))
    if not pending:
        return {"processed": 0, "near_duplicate_links": 0, "duplicates_marked": 0}
    pending_ids = {row["id"] for row in pending}
    text_ids = {row["id"] for row in pending if row["kind"] in {"article", "advisory"}}
    cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat(timespec="seconds")
    recent = list(ctx.db.execute("SELECT * FROM documents WHERE kind IN ('article', 'advisory') AND collected_at >= ?", (cutoff,)))
    corpus = {row["id"]: row for row in recent}
    recent_ids = set(corpus)
    corpus.update({row["id"]: row for row in pending if row["id"] in text_ids})
    affected = set(pending_ids)
    for row in ctx.db.execute("SELECT doc_a, doc_b FROM document_links WHERE reason='near_duplicate'"):
        if row["doc_a"] in pending_ids or row["doc_b"] in pending_ids:
            affected.update((row["doc_a"], row["doc_b"]))
    for document_id in pending_ids:
        ctx.db.execute("DELETE FROM document_links WHERE reason='near_duplicate' AND (doc_a=? OR doc_b=?)", (document_id, document_id))

    shingles = {doc_id: _shingles(row["text"]) for doc_id, row in corpus.items()}
    frequency = Counter(shingle for items in shingles.values() for shingle in items)
    limit = max(5, len(corpus) * 0.05)
    index: dict[tuple[str, ...], list[int]] = defaultdict(list)
    hashes: dict[str, list[int]] = defaultdict(list)
    for doc_id, row in corpus.items():
        shingles[doc_id] = {s for s in shingles[doc_id] if frequency[s] <= limit}
        for shingle in shingles[doc_id]:
            index[shingle].append(doc_id)
        hashes[row["content_hash"]].append(doc_id)
    considered: set[tuple[int, int]] = set()
    linked = 0
    for doc_id in sorted(text_ids):
        overlaps = Counter(other for shingle in shingles[doc_id] for other in index[shingle] if other != doc_id)
        candidates = set(overlaps) | set(hashes[corpus[doc_id]["content_hash"]])
        for other in candidates - {doc_id}:
            pair = tuple(sorted((doc_id, other)))
            if pair in considered:
                continue
            considered.add(pair)
            row_a, row_b = corpus[doc_id], corpus[other]
            if doc_id not in recent_ids and other not in recent_ids:
                continue
            if row_a["content_hash"] == row_b["content_hash"]:
                score, title_score = 1.0, 1.0
            else:
                # Tiny snippets cannot establish a substantive near-duplicate match.
                if min(len(shingles[doc_id]), len(shingles[other])) < 25:
                    continue
                intersection = overlaps[other]
                score = intersection / (len(shingles[doc_id]) + len(shingles[other]) - intersection)
                if score < 0.40:
                    continue
                title_score = SequenceMatcher(None, _title(row_a["title"]), _title(row_b["title"]), autojunk=False).ratio()
                if score < 0.60 and title_score < 0.75:
                    continue
            ctx.db.execute("""INSERT INTO document_links (doc_a, doc_b, reason, detail, score)
                              VALUES (?, ?, 'near_duplicate', ?, ?)
                              ON CONFLICT(doc_a, doc_b, reason) DO UPDATE SET detail=excluded.detail, score=excluded.score""",
                           (*pair, dumps({"method": "word_5gram_jaccard", "title_similarity": round(title_score, 4)}), score))
            affected.update(pair)
            linked += 1

    # Rebuild affected components, not a chain of duplicate pointers. A late-arriving
    # older original can become the root; revised content can leave a component.
    adjacency: dict[int, set[int]] = defaultdict(set)
    for row in ctx.db.execute("SELECT doc_a, doc_b FROM document_links WHERE reason='near_duplicate'"):
        adjacency[row["doc_a"]].add(row["doc_b"])
        adjacency[row["doc_b"]].add(row["doc_a"])
    documents = {row["id"]: row for row in ctx.db.execute("SELECT id, published_at, collected_at, duplicate_of FROM documents")}
    visited = set()
    marked = 0
    for start in sorted(affected):
        if start in visited:
            continue
        component = set()
        todo = [start]
        while todo:
            current = todo.pop()
            if current in component:
                continue
            component.add(current)
            todo.extend(adjacency[current] - component)
        visited.update(component)
        original = min(component, key=lambda doc_id: (documents[doc_id]["published_at"] or documents[doc_id]["collected_at"], documents[doc_id]["collected_at"], doc_id))
        for doc_id in component:
            duplicate_of = None if doc_id == original else original
            if documents[doc_id]["duplicate_of"] != duplicate_of:
                ctx.db.execute("UPDATE documents SET duplicate_of=? WHERE id=?", (duplicate_of, doc_id))
                marked += duplicate_of is not None
    ctx.db.executemany("UPDATE documents SET processed_version=? WHERE id=?", [(row["version"], row["id"]) for row in pending])
    ctx.db.commit()
    ctx.log.info("process: %d versions processed, %d near-duplicate links, %d duplicates newly marked", len(pending), linked, marked)
    return {"processed": len(pending), "near_duplicate_links": linked, "duplicates_marked": marked}
