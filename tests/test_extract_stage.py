import json
import os
import time
from datetime import UTC, datetime, timedelta

import pytest

from tipipeline import process
from tipipeline.attack import Attack, Technique
from tipipeline.collect import Document, _store
from tipipeline.db import connect, init_db, upsert_indicator
from tipipeline.extract import extract_document, run
from tipipeline.extract import warninglists
from tipipeline.extract.benign import Allowlist
from tipipeline.extract.warninglists import WarningList, load
from tipipeline.llm import FakeBackend
from tipipeline.models import Settings
from tipipeline.pipeline import Context


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    context = Context(root=tmp_path, settings=Settings(), sources=[], profiles=[], db=conn, llm=FakeBackend({}))
    context.__dict__["attack"] = Attack({"T1059": Technique("T1059", "Command and Scripting Interpreter", (), "https://attack.mitre.org/techniques/T1059/", False)})
    names = ("fixture-hosts", "fixture-cidr", "fixture-hashes")
    monkeypatch.setattr(warninglists, "WARNINGLIST_NAMES", names)
    directory = context.cache_dir / "warninglists"
    directory.mkdir(parents=True)
    for name, type_, values in [(names[0], "hostname", ["google.com"]), (names[1], "cidr", ["8.8.8.0/24"]), (names[2], "string", ["1"*31 + "2"])]:
        (directory / f"{name}.json").write_text(json.dumps({"type": type_, "list": values}))
    monkeypatch.setattr(warninglists.httpx, "get", lambda *a, **k: pytest.fail("unexpected network request"))
    yield context
    conn.close()


def add_document(ctx, text="", kind="article", metadata=None, duplicate=None, url="https://vendor.com/research"):
    serial = ctx.db.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    cur = ctx.db.execute("""INSERT INTO documents(source_id,kind,tier,url,canonical_url,title,published_at,collected_at,updated_at,content_hash,text,meta_json,duplicate_of)
        VALUES ('test',?,'research',?,?,'Example report','2026-10-01T00:00:00Z','2026-10-02T00:00:00Z','2026-10-02T00:00:00Z',?,?,?,?)""",
                         (kind, url, url + f"?id={serial}", str(serial), text, json.dumps(metadata or {}), duplicate))
    ctx.db.commit()
    return cur.lastrowid


def rows(ctx, document_id):
    return {(row["type"], row["value"]): row for row in ctx.db.execute("""SELECT i.*,di.context,di.warninglist FROM document_indicators di
        JOIN indicators i ON i.id=di.indicator_id WHERE document_id=?""", (document_id,))}


def test_real_stage_flags_without_dropping_and_extracts_explicit_ids(ctx):
    document = add_document(ctx, "IOCs\nevil.net 8.8.8.8 sub.google.com vendor.com https://vendor.com/download\nT1059 T9999")
    stats = run(ctx)
    items = rows(ctx, document)
    assert items["domain", "evil.net"]["warninglist"] is None
    assert items["domain", "sub.google.com"]["warninglist"] == "fixture-hosts"
    assert items["ipv4", "8.8.8.8"]["warninglist"] == "fixture-cidr"
    assert items["domain", "vendor.com"]["warninglist"] == "publisher"
    assert items["url", "https://vendor.com/download"]["warninglist"] == "publisher"
    assert stats["flagged"] == 4
    assert dict(ctx.db.execute("SELECT technique_id,valid FROM document_techniques")) == {"T1059": 1, "T9999": 0}
    assert ctx.db.execute("SELECT extracted_version FROM documents WHERE id=?", (document,)).fetchone()[0] == 1
    assert items["domain", "evil.net"]["first_seen"] == "2026-10-01T00:00:00+00:00"
    assert run(ctx)["documents"] == 0


def write_allowlist(ctx, domains=(), platforms=()):
    path = ctx.root / "config" / "allowlist.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"domains": list(domains), "platforms": list(platforms)}))
    return path


def test_allowlist_and_publisher_flags_follow_registered_domain(ctx):
    write_allowlist(ctx, domains=["cisa.gov"], platforms=["github.com"])
    report = add_document(ctx, "IOCs\nwww.cisa.gov https://www.cisa.gov/news analyst@cisa.gov github.com evil.net\n"
                               "https://github.com/actor/tool/releases/x.exe cisa.gov.evil.net", url="https://blog.vendor.com/a")
    publisher = add_document(ctx, "IOCs\nraw.github.com https://gist.github.com/actor/1", url="https://github.com/blog/post")
    google = add_document(ctx, "IOCs\nsub.google.com", url="https://cloud.google.com/blog/x")
    run(ctx)
    assert {key: row["warninglist"] for key, row in rows(ctx, report).items()} == {
        ("domain", "www.cisa.gov"): "allowlist", ("url", "https://www.cisa.gov/news"): "allowlist",
        ("email", "analyst@cisa.gov"): "allowlist", ("domain", "github.com"): "allowlist",
        ("url", "https://github.com/actor/tool/releases/x.exe"): None, ("domain", "evil.net"): None,
        ("domain", "cisa.gov.evil.net"): None,
    }
    flags = {key: row["warninglist"] for key, row in rows(ctx, publisher).items()}
    assert flags == {("domain", "raw.github.com"): "publisher", ("url", "https://gist.github.com/actor/1"): None,
                     ("domain", "gist.github.com"): "publisher"}
    # A MISP list match wins over the publisher check.
    assert rows(ctx, google)["domain", "sub.google.com"]["warninglist"] == "fixture-hosts"


def test_allowlist_rejects_entries_that_are_not_registered_domains(tmp_path):
    path = tmp_path / "allowlist.yaml"
    path.write_text("domains: [www.cisa.gov]\n")
    with pytest.raises(ValueError):
        Allowlist.load(path)
    path.write_text("domains: [CISA.gov]\nplatforms: [github.com]\n")
    assert Allowlist.load(path) == Allowlist(frozenset({"cisa.gov"}), frozenset({"github.com"}))
    assert Allowlist.load(tmp_path / "missing.yaml") == Allowlist()


def test_extract_document_touches_only_that_document(ctx):
    write_allowlist(ctx, domains=["cisa.gov"])
    first = add_document(ctx, "IOCs\nold-c2.net")
    run(ctx)
    ctx.db.execute("UPDATE document_indicators SET warninglist='stale-flag' WHERE document_id=?", (first,))
    ctx.db.commit()
    second = add_document(ctx, "IOCs\nnew-c2.net cisa.gov T1059")
    assert extract_document(ctx, second) == {"domain": 2}
    assert {key: row["warninglist"] for key, row in rows(ctx, second).items()} == {("domain", "new-c2.net"): None,
                                                                                   ("domain", "cisa.gov"): "allowlist"}
    assert rows(ctx, first)["domain", "old-c2.net"]["warninglist"] == "stale-flag"
    assert ctx.db.execute("SELECT extracted_version FROM documents WHERE id=?", (second,)).fetchone()[0] == 1
    assert ctx.db.execute("SELECT technique_id FROM document_techniques WHERE document_id=?", (second,)).fetchone()[0] == "T1059"


def test_structured_metadata_types_and_contexts(ctx):
    kev = add_document(ctx, kind="vulnerability", metadata={"cveID": "CVE-2026-1234", "shortDescription": "Known exploit"})
    feed = add_document(ctx, kind="ioc_batch", metadata={"iocs": [
        {"ioc_type": "ip:port", "ioc": "9.9.9.9:443"}, {"ioc_type": "ip:port", "ioc": "[2606:4700::1111]:443"},
        {"ioc_type": "ip:port", "ioc": "127.0.0.1:80"}, {"ioc_type": "domain", "ioc": "evil[.]net"},
        {"ioc_type": "url", "ioc": "hxxps://evil.net/path"}, {"ioc_type": "md5_hash", "ioc": "12"*16},
        {"ioc_type": "sha1_hash", "ioc": "AB"*20}, {"ioc_type": "sha256_hash", "ioc": "CD"*32},
        {"ioc_type": "unknown", "ioc": "ignored"}]})
    run(ctx)
    assert rows(ctx, kev)["cve", "CVE-2026-1234"]["context"] == "metadata"
    items = rows(ctx, feed)
    assert set(type_ for type_, value in items) == {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    assert all(row["context"] == "feed" for row in items.values())
    assert ("sha1", "ab"*20) in items
    assert ("ipv4", "127.0.0.1") not in items


def test_reextraction_replaces_observations_and_only_explicit_techniques(ctx):
    document = add_document(ctx, "IOCs\nold.net T1059")
    run(ctx)
    ctx.db.execute("INSERT INTO document_techniques(document_id,technique_id,source,valid) VALUES (?,'T1059','llm',1)", (document,))
    ctx.db.execute("UPDATE documents SET text='IOCs\nnew.net T9999',version=version+1 WHERE id=?", (document,))
    run(ctx)
    assert set(rows(ctx, document)) == {("domain", "new.net")}
    assert {tuple(row) for row in ctx.db.execute("SELECT technique_id,source FROM document_techniques")} == {("T9999", "explicit"), ("T1059", "llm")}
    duplicate = add_document(ctx, "IOCs\nevil.net", duplicate=document)
    assert run(ctx)["duplicates_skipped"] == 1
    assert not rows(ctx, duplicate)
    ctx.db.execute("UPDATE documents SET duplicate_of=? WHERE id=?", (duplicate, document))
    run(ctx)
    assert not rows(ctx, document)


def test_document_promoted_from_duplicate_is_extracted(ctx):
    def store(url, text, age):
        published = (datetime.now(UTC) - timedelta(days=age)).isoformat(timespec="seconds")
        return _store(ctx, Document("test", "research", "article", url, url, "Report", text, published))[0]
    original = store("https://a.test/report", "IOCs\nevil.net T1059", 3)
    copy = store("https://b.test/report", "IOCs\nevil.net T1059", 1)
    process.run(ctx)
    run(ctx)
    assert ctx.db.execute("SELECT duplicate_of FROM documents WHERE id=?", (copy,)).fetchone()[0] == original
    assert not rows(ctx, copy)
    store("https://a.test/report", "IOCs\nother.net", 3)  # the original changes, so the copy is no longer a duplicate
    process.run(ctx)
    run(ctx)
    assert ctx.db.execute("SELECT duplicate_of FROM documents WHERE id=?", (copy,)).fetchone()[0] is None
    assert set(rows(ctx, copy)) == {("domain", "evil.net")}
    assert [tuple(r) for r in ctx.db.execute("SELECT technique_id,source FROM document_techniques WHERE document_id=?", (copy,))] == [("T1059", "explicit")]


def test_reextraction_removes_indicators_no_document_links_any_more(ctx):
    first = add_document(ctx, "IOCs\nshared.net only-first.net")
    add_document(ctx, "IOCs\nshared.net")
    run(ctx)
    ctx.db.execute("UPDATE documents SET text='IOCs\nshared.net',version=version+1 WHERE id=?", (first,))
    assert run(ctx)["unlinked_indicators_removed"] == 1
    assert {row[0] for row in ctx.db.execute("SELECT value FROM indicators")} == {"shared.net"}
    assert run(ctx)["unlinked_indicators_removed"] == 0


def test_warninglist_hostname_cidr_strings_and_other_matchers():
    hosts = WarningList.from_json("host", {"type": "hostname", "list": ["google.com"]})
    assert hosts.matches("domain", "sub.google.com")
    assert hosts.matches("url", "https://deep.sub.google.com/x")
    assert not hosts.matches("domain", "notgoogle.com")
    assert not hosts.matches("domain", "google.com.evil.net")
    cidr = WarningList.from_json("ip", {"type": "cidr", "list": ["8.8.8.0/24", "2606:4700::/32"]})
    assert cidr.matches("ipv4", "8.8.8.255")
    assert not cidr.matches("ipv4", "8.8.9.0")
    assert cidr.matches("url", "https://[2606:4700::1]/a")
    strings = WarningList.from_json("strings", {"type": "string", "list": ["ABC123", ".microsoft.com"]})
    assert strings.matches("sha256", "abc123")
    assert not strings.matches("sha256", "0abc123")
    assert strings.matches("domain", "foo.microsoft.com")
    assert strings.matches("url", "https://microsoft.com/a")
    assert not strings.matches("domain", "notmicrosoft.com")
    assert WarningList.from_json("sub", {"type": "substring", "list": ["benign"]}).matches("url", "https://x.net/benign-path")
    assert WarningList.from_json("rx", {"type": "regex", "list": [r"^test\d+\.net$"]}).matches("domain", "test123.net")
    hosting = WarningList.from_json("tranco", {"type": "hostname", "list": ["pages.dev", "blogspot.com"]})
    assert hosting.matches("domain", "pages.dev")
    assert not hosting.matches("domain", "my-662ylt3w.pages.dev")
    assert not hosting.matches("url", "https://a.b.evil.blogspot.com/x")
    tenant = WarningList.from_json("strings", {"type": "string", "list": [".workers.dev", "app.eduac.workers.dev"]})
    assert not tenant.matches("domain", "x.daoahueb.workers.dev")
    assert tenant.matches("domain", "app.eduac.workers.dev")


def test_expired_cache_refresh_updates_unchanged_document(ctx, monkeypatch):
    document = add_document(ctx, "IOCs\nevil.net")
    run(ctx)
    directory = ctx.cache_dir / "warninglists"
    path = directory / "fixture-hosts.json"
    os.utime(path, (time.time() - 8*86400, time.time() - 8*86400))
    class Response:
        text = json.dumps({"type": "hostname", "list": ["evil.net"]})
        def raise_for_status(self): pass
        def json(self): return json.loads(self.text)
    requested = []
    def get(url, **kwargs):
        requested.append(url)
        return Response()
    monkeypatch.setattr(warninglists.httpx, "get", get)
    assert run(ctx)["documents"] == 0
    assert rows(ctx, document)["domain", "evil.net"]["warninglist"] == "fixture-hosts"
    assert len(requested) == 1
    assert load(ctx).unavailable == []
    assert len(requested) == 1


def test_unavailable_warninglist_surfaces_partial_not_silent_success(ctx, monkeypatch):
    add_document(ctx, "IOCs\nevil.net")
    path = ctx.cache_dir / "warninglists" / "fixture-hosts.json"
    path.unlink()
    def unavailable(*args, **kwargs):
        raise warninglists.httpx.ConnectError("network unavailable")
    monkeypatch.setattr(warninglists.httpx, "get", unavailable)
    stats = run(ctx)
    assert stats["status"] == "partial"
    assert stats["warninglists_unavailable"] == ["fixture-hosts"]
    assert stats["documents"] == 1
    assert stats["warninglists_loaded"] == 2


def test_regex_case_is_preserved_for_character_classes():
    regex = WarningList.from_json("regex", {"type": "regex", "list": [r"^\D+\.net$"]})
    assert regex.matches("domain", "alphabet.net")
    assert not regex.matches("domain", "123.net")
