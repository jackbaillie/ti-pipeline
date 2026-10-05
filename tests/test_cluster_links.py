from types import SimpleNamespace

import pytest

from tipipeline.cluster import MAX_DOCS_PER_SHARED_VALUE, run
from tipipeline.db import connect, init_db, upsert_indicator


@pytest.fixture
def ctx(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    yield SimpleNamespace(db=conn)
    conn.close()


def document(ctx, kind="article", duplicate=None):
    number = ctx.db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] + 1
    return ctx.db.execute("""INSERT INTO documents(source_id,kind,tier,url,canonical_url,title,collected_at,updated_at,content_hash,text,duplicate_of)
        VALUES ('test',?,'research',?,?,'test','2026-10-01','2026-10-01',?,'',?)""",
                         (kind, f"https://test.net/{number}", f"https://test.net/{number}", str(number), duplicate)).lastrowid


def indicator(ctx, docs, type_, value, warning=None):
    number = upsert_indicator(ctx.db, type_, value, "2026-10-01T00:00:00+00:00")
    for doc in docs:
        ctx.db.execute("INSERT INTO document_indicators(document_id,indicator_id,context,warninglist) VALUES (?,?,'ioc_section',?)", (doc, number, warning))
    return number


def clusters(ctx):
    return {row[0]: row[1] for row in ctx.db.execute("SELECT id,cluster_id FROM documents")}


def test_transitive_union_shared_cve_near_duplicate_and_threatfox(ctx):
    a, b, c = [document(ctx) for _ in range(3)]
    feed = document(ctx, "ioc_batch")
    dup = document(ctx, duplicate=b)
    solo = document(ctx)
    indicator(ctx, [a, b], "domain", "evil.net")
    indicator(ctx, [b, c], "cve", "CVE-2026-1234")
    indicator(ctx, [c, feed], "ipv4", "9.9.9.9")
    ctx.db.execute("INSERT INTO document_links(doc_a,doc_b,reason) VALUES (?,?,'near_duplicate')", (b, dup))
    stats = run(ctx)
    assert clusters(ctx) == {a: a, b: a, c: a, feed: a, dup: a, solo: solo}
    assert stats["clusters"] == 2
    assert stats["cluster_sizes"] == [5, 1]
    links = [tuple(row) for row in ctx.db.execute("SELECT doc_a,doc_b,reason,detail FROM document_links ORDER BY doc_a,doc_b,reason")]
    assert (b, c, "shared_cve", "CVE-2026-1234") in links
    assert (c, feed, "shared_indicator", "9.9.9.9") in links
    assert run(ctx)["cluster_sizes"] == stats["cluster_sizes"]
    assert [tuple(row) for row in ctx.db.execute("SELECT doc_a,doc_b,reason,detail FROM document_links ORDER BY doc_a,doc_b,reason")] == links


def test_common_value_cap_and_warninglisted_rows_do_not_make_giant_clusters(ctx):
    docs = [document(ctx) for _ in range(MAX_DOCS_PER_SHARED_VALUE + 1)]
    indicator(ctx, docs, "domain", "common.net")
    indicator(ctx, docs, "cve", "CVE-2026-9999")
    indicator(ctx, docs[:2], "ipv4", "8.8.8.8", "dns")
    stats = run(ctx)
    assert stats["ignored_common_indicators"] == 2
    assert stats["clusters"] == len(docs)
    assert ctx.db.execute("SELECT COUNT(*) FROM document_links").fetchone()[0] == 0
    ctx.db.execute("DELETE FROM document_indicators WHERE document_id=?", (docs[-1],))
    run(ctx)
    assert len(set(clusters(ctx).values())) == 2
    assert ctx.db.execute("SELECT COUNT(*) FROM document_links WHERE reason='shared_cve'").fetchone()[0] == 28


def test_rebuild_removes_stale_links_keeps_process_links_and_singletons(ctx):
    a, b, c = [document(ctx) for _ in range(3)]
    indicator_id = indicator(ctx, [a, b], "domain", "old.net")
    ctx.db.execute("INSERT INTO document_links(doc_a,doc_b,reason) VALUES (?,?,'near_duplicate')", (b, c))
    run(ctx)
    assert set(clusters(ctx).values()) == {a}
    ctx.db.execute("DELETE FROM document_indicators WHERE indicator_id=?", (indicator_id,))
    run(ctx)
    assert clusters(ctx) == {a: a, b: b, c: b}
    assert [tuple(row) for row in ctx.db.execute("SELECT doc_a,doc_b,reason FROM document_links")] == [(b, c, "near_duplicate")]
