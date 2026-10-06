import json
from types import SimpleNamespace

import pytest

from tipipeline.cluster import MAX_DOCS_PER_SHARED_VALUE, run, story_members
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


def kev(ctx, vendor, product, added):
    doc = document(ctx, "vulnerability")
    ctx.db.execute("UPDATE documents SET meta_json=? WHERE id=?",
                   (json.dumps({"vendorProject": vendor, "product": product, "dateAdded": added}), doc))
    return doc


def typed(ctx, doc, report_type, title="test"):
    ctx.db.execute("UPDATE documents SET title=? WHERE id=?", (title, doc))
    ctx.db.execute("""INSERT INTO analyses(document_id,document_version,status,model,created_at,report_type)
        VALUES (?,1,'ok','fake','2026-10-01',?)""", (doc, report_type))
    return doc


def test_kev_entries_for_one_product_within_30_days_share_a_story_without_link_rows(ctx):
    first = kev(ctx, "Citrix", "NetScaler", "2026-09-09")
    second = kev(ctx, "Citrix", "NetScaler", "2026-09-27")
    third = kev(ctx, "citrix", "NetScaler ", "2026-10-04")
    later = kev(ctx, "Citrix", "NetScaler", "2026-11-20")
    other_product = kev(ctx, "Citrix", "ShareFile", "2026-09-27")
    other_vendor = kev(ctx, "Fortinet", "NetScaler", "2026-09-27")
    article = document(ctx)
    indicator(ctx, [article, third], "cve", "CVE-2026-88779")
    stats = run(ctx)
    found = clusters(ctx)
    assert found[first] == found[second] == found[third] == found[article]
    assert len({found[first], found[later], found[other_product], found[other_vendor]}) == 4
    assert stats["multi_document_stories"] == 1 and stats["largest_story"] == 4
    assert ctx.db.execute("SELECT COUNT(*) FROM document_links").fetchone()[0] == 1


@pytest.mark.parametrize("report_type,title,opening,cves", [
    ("roundup", "Weekly notes", "", 0),
    ("news", "5th October – Threat Intelligence Report", "", 0),
    (None, "The Week in Ransomware - October 2nd 2026", "", 0),
    (None, "Give yourself room to be human", "Welcome to this week’s edition of the Threat Source newsletter.", 0),
    ("vulnerability", "Microsoft Patch Tuesday for September 2026", "", 0),
    ("vulnerability", "September fixes", "", 10),
])
def test_roundups_and_bulletins_keep_link_rows_but_do_not_bridge_stories(ctx, report_type, title, opening, cves):
    netscaler, phishing, related = document(ctx), document(ctx), document(ctx)
    digest = document(ctx)
    ctx.db.execute("UPDATE documents SET title=?,text=? WHERE id=?", (title, opening, digest))
    if report_type: typed(ctx, digest, report_type, title)
    typed(ctx, related, "vulnerability", "Citrix patches NetScaler zero-day")
    indicator(ctx, [netscaler, digest], "cve", "CVE-2026-88771")
    indicator(ctx, [phishing, digest], "domain", "lure.net")
    indicator(ctx, [netscaler, related], "domain", "c2.net")
    for number in range(cves): indicator(ctx, [digest], "cve", f"CVE-2026-{1000 + number}")
    stats = run(ctx)
    found = clusters(ctx)
    assert found[netscaler] == found[related]
    assert len({found[netscaler], found[phishing], found[digest]}) == 3
    assert stats["kept_apart"] == 1 and stats["largest_story"] == 2
    pairs = {tuple(row) for row in ctx.db.execute("SELECT doc_a,doc_b FROM document_links")}
    assert {(netscaler, digest), (phishing, digest)} <= pairs


def test_story_members_for_an_unclustered_document(ctx):
    a, b, digest = document(ctx), document(ctx), document(ctx)
    typed(ctx, digest, "roundup")
    indicator(ctx, [a, b], "domain", "c2.net")
    run(ctx)
    assert story_members(ctx.db, a) == [a, b]
    new = document(ctx)
    indicator(ctx, [new, b], "ipv4", "9.9.9.9")
    indicator(ctx, [new, digest], "domain", "lure.net")
    indicator(ctx, [new], "domain", "flagged.net", "allowlist")
    assert story_members(ctx.db, new) == [a, b, new]
    assert story_members(ctx.db, digest) == [digest]
    assert story_members(ctx.db, 999) == []
