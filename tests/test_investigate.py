"""Manual investigations against the synthetic sample database; fake LLM, no network."""
from pathlib import Path

import httpx
import pytest

from tipipeline import collect
from tipipeline.config import load_table_schemas
from tipipeline.db import dumps, now_iso, upsert_indicator
from tipipeline.extract import warninglists
from tipipeline.investigate import (
    create_investigation,
    detect_kind,
    get_investigation,
    list_investigations,
    recover_interrupted,
    resolve_input,
    run_investigation,
    search_reports,
)
from tipipeline.models import InvestigationTerms

ROOT = Path(__file__).resolve().parents[1]
BEHAVIOURAL_KQL = (
    "let lookback = 30d;\nDeviceProcessEvents\n| where TimeGenerated >= ago(lookback)\n"
    '| where FileName =~ "powershell.exe"\n| project TimeGenerated, DeviceName, ProcessCommandLine'
)


def hunt_draft(prompt):
    return {
        "title": "Gateway exploitation followed by PowerShell",
        "hypothesis": "An intruder exploited the remote-access gateway and ran PowerShell on managed endpoints.",
        "scope": "Managed endpoints behind the remote-access gateway.",
        "pyramid_levels": ["ttps"],
        "queries": [{
            "title": "PowerShell on managed endpoints", "purpose": "Find PowerShell for review.",
            "technique_ids": ["T1059.001"], "tables": ["DeviceProcessEvents"], "kql": BEHAVIOURAL_KQL,
            "benign_explanations": ["Administrator scripts."], "pivots": ["Review the parent process."],
        }],
    }


@pytest.fixture
def ctx(sample_ctx):
    sample_ctx.run_id = None  # investigations run outside a pipeline run
    sample_ctx.__dict__["table_schemas"] = load_table_schemas(ROOT)
    sample_ctx.llm.responders["hunt"] = hunt_draft
    return sample_ctx


def run(ctx, value, **options):
    investigation = run_investigation(ctx, create_investigation(ctx, value, **options))
    assert investigation.status == "done", investigation.error
    return investigation.result


def add_document(ctx, *, title, cluster_id, technique=None, published="2026-10-05T12:00:00+00:00"):
    stamp = now_iso()
    cur = ctx.db.execute(
        """INSERT INTO documents (source_id, kind, tier, url, canonical_url, title, published_at, collected_at,
           updated_at, content_hash, text, cluster_id) VALUES ('news','article','news',?,?,?,?,?,?,'h','Body text.',?)""",
        (f"https://news.example/{title}", f"https://news.example/{title}", title, published, stamp, stamp, cluster_id),
    )
    if technique:
        ctx.db.execute(
            """INSERT INTO document_techniques (document_id, technique_id, source, basis, quote, quote_verified, valid)
               VALUES (?, ?, 'explicit', 'stated', ?, 1, 1)""", (cur.lastrowid, technique, technique),
        )
    ctx.db.commit()
    return cur.lastrowid


def public_dns(monkeypatch, address="93.184.215.14"):
    monkeypatch.setattr(collect.socket, "getaddrinfo", lambda host, port, **kw: [(2, 1, 6, "", (address, port))])


def mock_http(monkeypatch, handler):
    client = httpx.Client
    monkeypatch.setattr(collect.httpx, "Client", lambda **kw: client(transport=httpx.MockTransport(handler), **kw))


@pytest.mark.parametrize(("value", "kind"), [
    ("https://research.example/report?id=1", "url"),
    ("cve-2025-5777", "cve"),
    ("T1133", "technique"),
    ("t1059.001", "technique"),
    ("Attackers reuse stolen NetScaler sessions", "hypothesis"),
    ("CVE-2025-5777 exploited at law firms", "hypothesis"),
])
def test_detect_kind(value, kind):
    assert detect_kind(value) == kind


def test_resolve_input_normalises_and_explains_bad_input():
    assert resolve_input("  cve-2025-5777 ") == ("cve", "CVE-2025-5777")
    assert resolve_input("t1059.001", "technique") == ("technique", "T1059.001")
    assert resolve_input("T1133", "hypothesis") == ("hypothesis", "T1133")
    for value, kind, message in [
        ("   ", "auto", "Enter"), ("x" * 2001, "auto", "2,000"), ("not a cve", "cve", "CVE-2025-5777"),
        ("T11", "technique", "T1133"), ("ftp://x.example/a", "url", "http"), ("hello", "domain", "Unknown"),
    ]:
        with pytest.raises(ValueError, match=message):
            resolve_input(value, kind)


def test_create_queues_and_rejects_unknown_customer(ctx):
    with pytest.raises(ValueError, match="Unknown customer"):
        create_investigation(ctx, "T1133", profile_id="nobody")
    investigation_id = create_investigation(ctx, "t1133", profile_id="law-firm", include_scraped=True)
    stored = get_investigation(ctx.db, investigation_id)
    assert (stored.kind, stored.input, stored.profile_id, stored.include_scraped, stored.status) == (
        "technique", "T1133", "law-firm", True, "queued")
    assert stored.active and [i.id for i in list_investigations(ctx.db)] == [investigation_id]


def test_cve_investigation_uses_reports_and_kev_entry(ctx):
    result = run(ctx, "CVE-2026-23456", profile_id="manufacturer-ot")
    assert [[r["id"] for r in story["reports"]] for story in result["stories"]] == [[2]]
    assert result["stories"][0]["reports"][0]["reasons"] == ["mentions CVE-2026-23456"]
    assert result["kev"]["document_id"] == 8 and ["Vendor", "Fortinet"] in result["kev"]["fields"]
    assert "CISA lists it as known exploited: Fortinet FortiOS" in result["focus"]
    assert result["cves"] == [{"id": "CVE-2026-23456", "reports": 1, "kev": True}]
    assert {t["id"] for t in result["techniques"]} == {"T1133", "T1486"}
    assert [q["title"] for q in result["hunt"]["queries"]] == ["PowerShell on managed endpoints"]
    task, prompt = ctx.llm.prompts[-1]
    assert task == "hunt" and "CVE-2026-23456" in prompt
    # Model calls made outside a pipeline run are still recorded.
    assert ctx.db.execute("SELECT task, run_id FROM llm_calls ORDER BY id DESC LIMIT 1").fetchone()[:] == ("hunt", None)


def test_cve_with_only_a_kev_entry_does_not_make_a_generic_hunt(ctx):
    result = run(ctx, "CVE-2026-12345")
    assert result["stories"] == [] and result["kev"]["document_id"] == 3 and result["empty"] is None
    assert result["hunt"] is None and result["hunt_error"].startswith("No source-supported hunt could be drafted")
    assert ctx.llm.prompts == []


def test_nothing_found_is_done_without_a_model_call(ctx):
    result = run(ctx, "CVE-2020-0001")
    assert result["empty"].startswith("No collected reports mention CVE-2020-0001")
    assert result["hunt"] is None and ctx.llm.prompts == []


def test_technique_parent_includes_sub_techniques_and_dedupes_stories(ctx):
    # One more report in story 1 and one elsewhere; the near-duplicate (5) never shows.
    same_story = add_document(ctx, title="netscaler-follow-up", cluster_id=1, technique="T1059.003")
    elsewhere = add_document(ctx, title="unrelated-powershell", cluster_id=None, technique="T1059",
                             published="2026-09-30T08:00:00+00:00")
    result = run(ctx, "T1059")
    stories = {story["id"]: [r["id"] for r in story["reports"]] for story in result["stories"]}
    assert stories == {1: [same_story, 1], elsewhere: [elsewhere]}
    reasons = {r["id"]: r["reasons"] for story in result["stories"] for r in story["reports"]}
    assert reasons[1] == ["T1059.001"] and reasons[elsewhere] == ["T1059"]
    assert "ATT&CK T1059" in result["focus"] and "sub-techniques" in result["focus"]
    assert run(ctx, "T1059.001")["report_count"] == 1


def test_include_scraped_adds_body_indicators(ctx):
    indicator_id = upsert_indicator(ctx.db, "domain", "scraped-example.org", now_iso())
    ctx.db.execute("INSERT INTO document_indicators (document_id, indicator_id, context) VALUES (1, ?, 'body')", (indicator_id,))
    ctx.db.commit()

    qualified = run(ctx, "T1190")
    values = {i["value"] for i in qualified["iocs"]}
    assert "198.51.100.42" in values and "scraped-example.org" not in values
    # 8.8.8.8 and login.microsoftonline.com are warninglisted body indicators.
    assert "8.8.8.8" not in values and qualified["iocs_benign"] == 2
    assert qualified["iocs_scraped_hidden"] == 1
    ip = next(i for i in qualified["iocs"] if i["value"] == "198.51.100.42")
    assert ip["display"] == "198[.]51[.]100[.]42" and ip["reports"] == [1] and ip["contexts"] == ["ioc_section"]

    scraped = run(ctx, "T1190", include_scraped=True)
    entry = next(i for i in scraped["iocs"] if i["value"] == "scraped-example.org")
    assert entry["contexts"] == ["body"] and scraped["iocs_scraped_hidden"] == 0
    sweeps = [q for q in scraped["hunt"]["queries"] if q["kind"] == "ioc_sweep"]
    assert any("scraped-example.org" in q["kql"] for q in sweeps)
    assert not any("scraped-example.org" in q["kql"] for q in qualified["hunt"]["queries"])


def test_hypothesis_terms_drive_the_search(ctx):
    ctx.llm.responders["investigation_terms"] = lambda prompt: {
        "keywords": ["NetScaler", "NetScaler", "ab"], "products": ["FortiOS"],
        "technique_ids": ["T1133", "T9999"], "cves": [],
    }
    hypothesis = "Attackers chain NetScaler access with CVE-2026-23456 to reach file shares"
    result = run(ctx, hypothesis)
    assert result["terms"] == {"keywords": ["NetScaler"], "products": ["FortiOS"],
                               "technique_ids": ["T1133"], "cves": ["CVE-2026-23456"]}
    assert "Hypothesis:\n<<<\n" + hypothesis in ctx.llm.prompts[0][1]
    ranked = [r["id"] for story in result["stories"] for r in story["reports"]]
    # Doc 2: T1133 + the CVE; doc 8: FortiOS title + the CVE; doc 3: NetScaler title; doc 1: NetScaler in text.
    assert ranked[:2] == [8, 2] and set(ranked) == {1, 2, 3, 8}
    assert len(result["stories"]) == 2  # stories 1 (docs 1, 3) and 2 (docs 2, 8)
    reasons = {r["id"]: r["reasons"] for story in result["stories"] for r in story["reports"]}
    assert reasons[1] == ["NetScaler (text)"] and reasons[3] == ["NetScaler (title)"]
    assert result["focus"] == f"Analyst hypothesis: {hypothesis}"


def test_hypothesis_search_escapes_like_wildcards(ctx):
    terms = InvestigationTerms(keywords=["%_%"], products=[], technique_ids=[], cves=[])
    assert search_reports(ctx.db, terms) == {}


def test_failed_term_extraction_marks_the_investigation_as_error(ctx):
    investigation = run_investigation(ctx, create_investigation(ctx, "Something odd on the file servers"))
    assert investigation.status == "error" and "investigation_terms" in investigation.error


def test_failed_hunt_draft_keeps_the_evidence(ctx):
    del ctx.llm.responders["hunt"]
    result = run(ctx, "T1133")
    assert [r["id"] for s in result["stories"] for r in s["reports"]] == [2]
    assert result["hunt"] is None and "no fake response" in result["hunt_error"]


def test_url_investigation_fetches_extracts_analyses_and_joins_the_story(ctx, monkeypatch):
    monkeypatch.setattr(warninglists, "WARNINGLIST_NAMES", ())
    public_dns(monkeypatch)
    article = (
        "<html><head><title>Gateway intrusion update</title></head><body><article><h1>Gateway intrusion update</h1>"
        + "<p>The intruders staged tools on the gateway and called back to their infrastructure.</p>" * 12
        + "<h2>Indicators of compromise</h2><p>updates-example[.]net</p></article></body></html>"
    )
    mock_http(monkeypatch, lambda request: httpx.Response(200, text=article))
    ctx.llm.responders["analysis"] = lambda prompt: {
        "summary": "Intruders staged tools on a gateway.", "report_type": "incident", "huntable": True,
        "huntable_reason": "Concrete infrastructure.", "threat_actors": [], "malware": [], "tools": [],
        "affected_technologies": [], "cves": [], "targeted_sectors": [], "targeted_regions": [], "attack_steps": [],
    }
    result = run(ctx, "https://research.example/gateway-update")
    [story] = result["stories"]
    submitted, *others = story["reports"]
    assert submitted["reasons"] == ["submitted report"] and submitted["source"] == "Manual submission"
    assert submitted["summary"] == "Intruders staged tools on a gateway."
    # updates-example.net links the new report to story 1 (docs 1, 3, 4); the near-duplicate 5 is left out.
    assert sorted(r["id"] for r in others) == [1, 3, 4]
    assert [task for task, _ in ctx.llm.prompts] == ["analysis", "hunt"]
    stored = ctx.db.execute("SELECT tier, extracted_version FROM documents WHERE id = ?", (submitted["id"],)).fetchone()
    assert stored[:] == ("manual", 1)


def test_url_investigation_refuses_private_addresses(ctx, monkeypatch):
    public_dns(monkeypatch, "192.168.1.10")
    mock_http(monkeypatch, lambda request: pytest.fail("no request may be sent"))
    investigation = run_investigation(ctx, create_investigation(ctx, "https://intranet.example/report"))
    assert investigation.status == "error" and "non-public address 192.168.1.10" in investigation.error


def test_restart_fails_running_and_resumes_queued(ctx):
    running = create_investigation(ctx, "T1133")
    queued = create_investigation(ctx, "T1190")
    ctx.db.execute("UPDATE investigations SET status = 'running' WHERE id = ?", (running,))
    ctx.db.commit()
    assert recover_interrupted(ctx.db) == [queued]
    interrupted = get_investigation(ctx.db, running)
    assert interrupted.status == "error" and interrupted.error.startswith("Interrupted")


def test_result_is_stored_as_json(ctx):
    investigation_id = create_investigation(ctx, "T1133")
    run_investigation(ctx, investigation_id)
    raw = ctx.db.execute("SELECT result_json FROM investigations WHERE id = ?", (investigation_id,)).fetchone()[0]
    assert raw == dumps(get_investigation(ctx.db, investigation_id).result)


def analysis_response(ctx):
    import json
    return json.loads(ctx.db.execute("SELECT analysis_json FROM analyses WHERE document_id=2").fetchone()[0])


def test_stale_analysis_is_refreshed_before_display_and_drafting(ctx):
    response = analysis_response(ctx)
    response["summary"] = "Current report analysis."
    ctx.llm.responders["analysis"] = lambda prompt: response
    ctx.db.execute("UPDATE documents SET version=version+1 WHERE id=2")
    ctx.db.commit()
    result = run(ctx, "T1133")
    report = result["stories"][0]["reports"][0]
    assert report["summary"] == "Current report analysis."
    assert [task for task, _ in ctx.llm.prompts] == ["analysis", "hunt"]
    assert result["hunt"]["sources"] == [{"id": 2, "title": report["title"]}]
    versions = ctx.db.execute("SELECT d.version,a.document_version FROM documents d JOIN analyses a ON a.document_id=d.id WHERE d.id=2").fetchone()
    assert versions[0] == versions[1]


def test_failed_stale_refresh_cannot_display_old_summary_or_draft(ctx):
    ctx.db.execute("UPDATE documents SET version=version+1 WHERE id=2")
    ctx.db.commit()
    result = run(ctx, "T1133")
    assert result["stories"][0]["reports"][0]["summary"] == ""
    assert result["hunt"] is None and result["hunt_error"].startswith("No source-supported hunt could be drafted")
    assert [task for task, _ in ctx.llm.prompts] == ["analysis"]


def test_on_demand_analysis_is_bounded_and_identifies_actual_sources(ctx):
    response = analysis_response(ctx)
    ctx.llm.responders["analysis"] = lambda prompt: response
    added = [add_document(ctx, title=f"extra-report-{i}", cluster_id=None, technique="T1133") for i in range(12)]
    result = run(ctx, "T1133")
    assert [task for task, _ in ctx.llm.prompts].count("analysis") == 10
    assert {s["id"] for s in result["hunt"]["sources"]} == {2, *added[2:]}
    assert any("2 additional matches did not inform the hunt" in note for note in result["notes"])


def test_empty_validated_query_set_is_not_a_successful_hunt(ctx):
    ctx.llm.responders["hunt"] = lambda prompt: {**hunt_draft(prompt), "queries": []}
    result = run(ctx, "T1133")  # this report has a CVE, but no sweepable IOCs
    assert result["hunt"] is None and "no queries passed the schema check" in result["hunt_error"]
    assert result["report_count"] == 1


def test_completed_page_names_the_source_reports_used(ctx):
    from tipipeline.dashboard.investigations import live_investigation
    investigation_id = create_investigation(ctx, "T1133")
    run_investigation(ctx, investigation_id)
    page = live_investigation(ctx, investigation_id)
    assert "Source reports supplied to the draft" in page and "Ransomware actors target manufacturing remote access" in page
    assert "General investigation" in page


def test_non_url_lookup_does_not_wait_for_pipeline_lock(ctx, monkeypatch):
    from tipipeline import investigate
    monkeypatch.setattr(investigate, "run_lock", lambda *a, **kw: pytest.fail("non-URL lookups must not take the run lock"))
    assert run(ctx, "CVE-2020-0001")["empty"]
