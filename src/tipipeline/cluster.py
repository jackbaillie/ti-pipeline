"""Evidence links and connected components, not campaign attribution.

Values mentioned by more than eight non-duplicate documents are ignored:
common infrastructure or ubiquitous CVEs must not collapse the corpus into
one giant component. Existing near-duplicate links remain process-owned.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations

MAX_DOCS_PER_SHARED_VALUE = 8


def run(ctx) -> dict:
    documents = ctx.db.execute("SELECT id,duplicate_of FROM documents ORDER BY id").fetchall()
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

    shared: dict[tuple[str, str], set[int]] = defaultdict(set)
    rows = ctx.db.execute("""SELECT di.document_id,i.type,i.value FROM document_indicators di
        JOIN indicators i ON i.id=di.indicator_id JOIN documents d ON d.id=di.document_id
        WHERE d.duplicate_of IS NULL AND di.warninglist IS NULL""")
    for row in rows: shared[row["type"], row["value"]].add(row["document_id"])
    links: dict[tuple[int, int, str], list[str]] = defaultdict(list)
    ignored = 0
    for (type_, value), document_ids in sorted(shared.items()):
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
    for link in ctx.db.execute("SELECT doc_a,doc_b FROM document_links"): union(link[0], link[1])
    for document in documents:
        if document["duplicate_of"] is not None: union(document["id"], document["duplicate_of"])
    for document in documents:
        ctx.db.execute("UPDATE documents SET cluster_id=? WHERE id=?", (find(document["id"]), document["id"]))
    ctx.db.commit()
    sizes = Counter(find(document["id"]) for document in documents)
    return {"documents": len(documents), "clusters": len(sizes), "singletons": sum(size == 1 for size in sizes.values()),
            "cluster_sizes": sorted(sizes.values(), reverse=True), "ignored_common_indicators": ignored,
            "links_by_reason": dict(Counter(key[2] for key in links))}
