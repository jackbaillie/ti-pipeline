import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
import stix2

from tipipeline.attack import Attack, Technique
from tipipeline.db import connect, init_db, upsert_indicator
from tipipeline.export import TTL_DAYS, confidence, run
from tipipeline.llm import FakeBackend
from tipipeline.models import Settings
from tipipeline.pipeline import Context


@pytest.fixture
def ctx(tmp_path):
    conn = connect(tmp_path / "t.db")
    init_db(conn)
    context = Context(root=tmp_path, settings=Settings(), sources=[], profiles=[], db=conn, llm=FakeBackend({}))
    context.__dict__["attack"] = Attack({
        "T1059": Technique("T1059", "Command and Scripting Interpreter", (), "https://attack.mitre.org/techniques/T1059/", False),
        "T1105": Technique("T1105", "Ingress Tool Transfer", (), "https://attack.mitre.org/techniques/T1105/", False),
    })
    yield context
    conn.close()


def document(ctx, kind="article", tier="research", metadata=None, duplicate=None):
    number = ctx.db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] + 1
    now = datetime.now(UTC).isoformat()
    return ctx.db.execute("""INSERT INTO documents(source_id,kind,tier,url,canonical_url,title,published_at,collected_at,updated_at,content_hash,text,meta_json,duplicate_of)
        VALUES (?,?,?, ?,?,'Research document',?,?,?,?, '',?,?)""",
                         (f"source-{number}", kind, tier, f"https://vendor.net/{number}", f"https://vendor.net/{number}", now, now, now, str(number), json.dumps(metadata or {}), duplicate)).lastrowid


def indicator(ctx, doc, type_, value, context="ioc_section", warning=None, seen=None):
    seen = seen or datetime.now(UTC).isoformat(timespec="seconds")
    number = upsert_indicator(ctx.db, type_, value, seen)
    ctx.db.execute("INSERT INTO document_indicators(document_id,indicator_id,context,warninglist) VALUES (?,?,?,?)", (doc, number, context, warning))
    return number


def bundle(ctx, name="active-indicators.json"):
    return stix2.parse((ctx.output_dir / "stix" / name).read_text())


def test_patterns_parse_all_types_flags_body_only_and_duplicates_excluded(ctx):
    doc = document(ctx)
    values = {"ipv4": "9.9.9.9", "ipv6": "2606:4700::1111", "domain": "evil.net", "url": "https://evil.net/a?q='x'",
              "email": "malware@evil.net", "md5": hashlib.md5(b"sample").hexdigest(),
              "sha1": hashlib.sha1(b"sample").hexdigest(), "sha256": hashlib.sha256(b"sample").hexdigest()}
    for type_, value in values.items(): indicator(ctx, doc, type_, value)
    indicator(ctx, doc, "ipv4", "8.8.8.8", warning="public-dns-v4")
    indicator(ctx, doc, "domain", "victim.net", context="body")
    indicator(ctx, doc, "cve", "CVE-2026-1234", context="metadata")
    dup = document(ctx, duplicate=doc)
    indicator(ctx, dup, "domain", "duplicate-only.net")
    ctx.db.execute("INSERT INTO document_techniques(document_id,technique_id,source,valid) VALUES (?,'T1059','explicit',1)", (doc,))
    ctx.db.execute("INSERT INTO document_techniques(document_id,technique_id,source,valid) VALUES (?,'T9999','explicit',0)", (doc,))
    stats = run(ctx)
    active = [item for item in bundle(ctx).objects if item.type == "indicator"]
    assert {item.name for item in active} == set(values.values())
    assert all(item.indicator_types == ["malicious-activity"] for item in active)
    assert all(item.external_references[0].url == f"https://vendor.net/{doc}" for item in active)
    report_bundle = bundle(ctx, f"documents/{doc}.json")
    reports = [item for item in report_bundle.objects if item.type == "report"]
    techniques = [item for item in report_bundle.objects if item.type == "attack-pattern"]
    assert len(reports) == len(techniques) == 1
    assert techniques[0].external_references[0].external_id == "T1059"
    assert {item.id for item in active} <= set(reports[0].object_refs)
    assert any(item.type == "vulnerability" for item in report_bundle.objects)
    assert stats["indicators"] == 8
    assert not (ctx.output_dir / "stix" / "documents" / f"{dup}.json").exists()
    assert any(item.id == stix2.TLP_WHITE.id for item in report_bundle.objects)


def test_body_observation_is_not_promoted_to_malicious_indicator(ctx):
    body = document(ctx)
    explicit = document(ctx)
    indicator(ctx, body, "domain", "victim.net", context="body")
    indicator(ctx, explicit, "domain", "c2.net", context="ioc_section")
    run(ctx)
    active = [item for item in bundle(ctx).objects if item.type == "indicator"]
    assert [item.name for item in active] == ["c2.net"]
    assert ctx.db.execute("SELECT COUNT(*) FROM document_indicators").fetchone()[0] == 2
    # A body-only report still has source provenance, not a fabricated IOC.
    report = [item for item in bundle(ctx, f"documents/{body}.json").objects if item.type == "report"][0]
    assert not any(reference.startswith("indicator--") for reference in report.object_refs)


def test_ttls_are_last_seen_plus_days_and_expired_kept_in_document_bundle(ctx):
    doc = document(ctx)
    now = datetime.now(UTC).replace(microsecond=0)
    first = now - timedelta(days=50)
    last = now - timedelta(days=2)
    ip = indicator(ctx, doc, "ipv4", "9.9.9.9", seen=first.isoformat())
    recent = document(ctx, kind="ioc_batch")
    indicator(ctx, recent, "ipv4", "9.9.9.9", context="feed", seen=last.isoformat())
    expired = document(ctx)
    old = now - timedelta(days=100)
    indicator(ctx, expired, "domain", "old.net", seen=old.isoformat())
    ctx.db.execute("UPDATE documents SET published_at=? WHERE id=?", (first.isoformat(), doc))
    ctx.db.execute("UPDATE documents SET published_at=NULL,collected_at=? WHERE id=?", (last.isoformat(), recent))
    ctx.db.execute("UPDATE documents SET published_at=? WHERE id=?", (old.isoformat(), expired))
    stats = run(ctx)
    active = [item for item in bundle(ctx).objects if item.type == "indicator"]
    assert len(active) == 1
    assert active[0].valid_from == first
    assert active[0].valid_until == last + timedelta(days=TTL_DAYS["ipv4"])
    assert stats["expired_indicators"] == 1
    assert len([item for item in bundle(ctx, f"documents/{doc}.json").objects if item.type == "indicator"]) == 1
    assert len([item for item in bundle(ctx, f"documents/{expired}.json").objects if item.type == "indicator"]) == 1
    assert ctx.db.execute("SELECT last_seen FROM indicators WHERE id=?", (ip,)).fetchone()[0] == last.isoformat()


def test_confidence_feed_blending_context_and_repeated_sources(ctx):
    feed = document(ctx, "ioc_batch", "ioc_feed", {"iocs": [{"ioc_type": "domain", "ioc": "feed.net", "confidence_level": 40}]})
    report = document(ctx)
    indicator(ctx, feed, "domain", "feed.net", context="feed")
    indicator(ctx, report, "domain", "report.net")
    run(ctx)
    active = {item.name: item for item in bundle(ctx).objects if item.type == "indicator"}
    assert active["feed.net"].confidence == 55
    assert active["report.net"].confidence == 90
    docs = {1: {"source_id": "one", "tier": "research", "id": 1}, 2: {"source_id": "two", "tier": "research", "id": 2}}
    row = {"document_id": 1, "context": "body", "type": "domain", "value": "evil.net"}
    explicit = {**row, "context": "ioc_section"}
    assert confidence([explicit], docs, {}) > confidence([row], docs, {})
    assert confidence([explicit, {**explicit, "document_id": 2}], docs, {}) == 90
    assert confidence([explicit, explicit, explicit], docs, {}) == 90
    docs[2]["source_id"] = docs[1]["source_id"]
    assert confidence([explicit, {**explicit, "document_id": 2}], docs, {}) == 90


def test_sentinel_batches_at_most_100_parse_and_stale_artifacts_removed(ctx):
    doc = document(ctx)
    for number in range(205): indicator(ctx, doc, "domain", f"c2-{number}.net")
    stats = run(ctx)
    directory = ctx.output_dir / "stix" / "sentinel-upload"
    files = sorted(directory.glob("batch-*.json"))
    assert stats["sentinel_batches"] == 3
    assert len(files) == 3
    sizes = []
    ids = set()
    for path in files:
        payload = json.loads(path.read_text())
        assert payload["sourcesystem"] == "ti-pipeline"
        assert 1 <= len(payload["stixobjects"]) <= 100
        sizes.append(len(payload["stixobjects"]))
        for item in payload["stixobjects"]:
            parsed = stix2.parse(item)
            ids.add(parsed.id)
    assert sizes == [100, 100, 6]
    assert len(ids) == 206
    indicator_ids = {item.id for item in bundle(ctx).objects if item.type == "indicator"}
    assert indicator_ids <= ids
    # Re-export IDs stay stable; removal updates both bundles and API envelopes.
    run(ctx)
    assert {item.id for item in bundle(ctx).objects if item.type == "indicator"} == indicator_ids
    ctx.db.execute("DELETE FROM document_indicators")
    ctx.db.execute("DELETE FROM documents")
    run(ctx)
    assert list(directory.glob("batch-*.json")) == []
    assert list((ctx.output_dir / "stix" / "documents").glob("*.json")) == []


def test_body_only_mentions_do_not_revive_expired_explicit_ip(ctx):
    now = datetime.now(UTC).replace(microsecond=0)
    explicit_date = now - timedelta(days=40)
    ancient_date = now - timedelta(days=400)
    explicit = document(ctx)
    body = document(ctx)
    ancient_body = document(ctx)
    ip = indicator(ctx, explicit, "ipv4", "9.9.9.9", seen=explicit_date.isoformat())
    indicator(ctx, body, "ipv4", "9.9.9.9", context="body", seen=now.isoformat())
    indicator(ctx, ancient_body, "ipv4", "9.9.9.9", context="body", seen=ancient_date.isoformat())
    ctx.db.execute("UPDATE documents SET published_at=? WHERE id=?", (explicit_date.isoformat(), explicit))
    ctx.db.execute("UPDATE documents SET published_at=? WHERE id=?", (now.isoformat(), body))
    ctx.db.execute("UPDATE documents SET published_at=? WHERE id=?", (ancient_date.isoformat(), ancient_body))
    stats = run(ctx)
    assert stats["active_indicators"] == 0
    assert stats["expired_indicators"] == 1
    assert not any(item.type == "indicator" for item in bundle(ctx).objects)
    exported = [item for item in bundle(ctx, f"documents/{explicit}.json").objects if item.type == "indicator"]
    assert len(exported) == 1
    assert exported[0].valid_from == explicit_date
    assert exported[0].valid_until == explicit_date + timedelta(days=30)
    assert ctx.db.execute("SELECT first_seen,last_seen FROM indicators WHERE id=?", (ip,)).fetchone()[:] == (
        ancient_date.isoformat(), now.isoformat())
    assert not any(item.type == "indicator" for item in bundle(ctx, f"documents/{body}.json").objects)


@pytest.mark.parametrize("analysis_version,status,include_llm", [
    (1, "ok", False), (2, "error", False), (None, None, False), (2, "ok", True),
])
def test_llm_techniques_require_current_successful_analysis_but_explicit_remain(ctx, analysis_version, status, include_llm):
    doc = document(ctx)
    ctx.llm_enabled = False
    ctx.db.execute("UPDATE documents SET version=2,extracted_version=2 WHERE id=?", (doc,))
    ctx.db.execute("INSERT INTO document_techniques(document_id,technique_id,source,valid) VALUES (?,'T1059','explicit',1)", (doc,))
    ctx.db.execute("INSERT INTO document_techniques(document_id,technique_id,source,valid) VALUES (?,'T1105','llm',1)", (doc,))
    if analysis_version is not None:
        ctx.db.execute("""INSERT INTO analyses(document_id,document_version,status,model,created_at)
                          VALUES (?,?,?,'test','2026-10-05T00:00:00Z')""", (doc, analysis_version, status))
    run(ctx)
    objects = bundle(ctx, f"documents/{doc}.json").objects
    attack_patterns = {item.external_references[0].external_id: item for item in objects if item.type == "attack-pattern"}
    assert set(attack_patterns) == ({"T1059", "T1105"} if include_llm else {"T1059"})
    report = next(item for item in objects if item.type == "report")
    assert set(report.object_refs) == {item.id for item in attack_patterns.values()}
