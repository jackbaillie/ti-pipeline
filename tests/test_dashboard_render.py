"""Dashboard behavior against a synthetic database, never the live pipeline DB."""
import re
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import urlsplit

from tipipeline.dashboard import _overview, generate, next_run, page_shell
from tipipeline.report import generate as report_generate
from tipipeline.report.data import snapshot_from_context


class PageParser(HTMLParser):
    """Links, their labels, table row attributes, and the surrounding details tree."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.link_labels = []
        self.script_tags = []
        self.rows = {}
        self.collapsed_links = []
        self.open_links = []
        self.story_ids = []
        self.tree_links = []
        self._table = None
        self._details = []
        self._link = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            href = attrs["href"]
            self.links.append(href)
            self._link = [href, ""]
            (self.collapsed_links if any(not is_open for is_open in self._details) else self.open_links).append(href)
            if "documents/" in href and len(self._details) >= 2:
                self.tree_links.append(href)
        if tag == "script":
            self.script_tags.append(attrs)
        if tag == "table":
            self._table = attrs.get("id")
            self.rows.setdefault(self._table, [])
        if tag == "tr" and self._table is not None:
            self.rows[self._table].append(attrs)
        if tag == "details":
            self._details.append("open" in attrs)
        if tag == "li" and "story" in attrs.get("class", "").split():
            self.story_ids.append(attrs["id"])

    def handle_data(self, data):
        if self._link is not None:
            self._link[1] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._link is not None:
            self.link_labels.append(tuple(self._link))
            self._link = None
        if tag == "table":
            self._table = None
        if tag == "details" and self._details:
            self._details.pop()


def parse(path):
    parser = PageParser()
    parser.feed(path.read_text())
    return parser


def test_dashboard_renders_complete_local_site(sample_ctx, sample_now):
    report_generate(sample_ctx, now=sample_now)
    stats = generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    assert stats == {"pages": 25, "documents": 9, "hunts": 5, "profiles": 3}
    expected = ["index.html", "reports.html", "hunts.html", "investigate.html", "iocs.html", "cves.html",
                "attack.html", "pipeline.html", "style.css", "app.js", "profiles/law-firm.html",
                "profiles/retail-bank.html", "profiles/manufacturer-ot.html", "documents/1.html",
                "documents/6.html", "hunts/1.html", "hunts/3.html"]
    for name in expected:
        assert (root / name).is_file()
    for page in root.rglob("*.html"):
        parser = parse(page)
        for href in parser.links:
            parts = urlsplit(href)
            if parts.scheme or not parts.path:
                continue
            assert (page.parent / parts.path).exists(), f"Broken relative link: {page.name}: {href}"
        assert all(tag.get("src") and not urlsplit(tag["src"]).scheme for tag in parser.script_tags)
        for href, label in parser.link_labels:
            if "documents/" in href:
                assert not re.fullmatch(r"\s*(?:Document\s+|#)\d+\s*", label, re.I), label
        assert not re.search(r"Document \d+", page.read_text())
    assert "HTTP 403" in (root / "pipeline.html").read_text()
    assert sample_ctx.llm.prompts == []


def test_overview_stories_are_clustered_and_ranked_by_score(sample_ctx, sample_now):
    s = snapshot_from_context(sample_ctx, sample_now)
    assert len(s.stories) == 5
    first = s.stories[0]
    assert {d.id for d in first.members} == {1, 3, 4, 5}
    # The analysed article beats the higher-scoring KEV record as the headline.
    assert first.lead.id == 1
    assert first.sources == 4
    assert first.score == 95 and first.priority == "high"
    assert first.cves == ["CVE-2026-12345"]
    assert "Citrix NetScaler Gateway" in first.products
    assert {h.id for h in first.hunts} == {1, 2, 3}
    law = first.impact("law-firm")
    assert law.document_id == 3 and law.score == 95
    assert [t.id for t in law.themes] == ["edge"]
    generate(sample_ctx, now=sample_now)
    page = sample_ctx.output_dir / "dashboard/index.html"
    parser = parse(page)
    assert parser.story_ids == ["story-1", "story-2", "story-7", "story-9"]
    text = page.read_text()
    for profile in sample_ctx.profiles:
        assert profile.short_name in text
        assert f'profiles/{profile.id}.html' in parser.links
    assert 'class="impact impact-high"' in text
    assert "+3 related" in text
    assert "Snapshot" not in text and "finished" not in text
    assert "Next run" in text
    assert "View 3 hunts" in text
    assert {"hunts/1.html", "hunts/2.html", "hunts/3.html"} <= set(parser.collapsed_links)


def test_overview_counts_only_the_period_without_invented_deltas(sample_ctx, sample_now):
    old = (sample_now - timedelta(days=45)).isoformat()
    sample_ctx.db.execute("UPDATE documents SET published_at=?, collected_at=? WHERE id=7", (old, old))
    sample_ctx.db.execute("UPDATE hunts SET created_at=? WHERE id=5", (old,))
    sample_ctx.db.execute("UPDATE indicators SET first_seen=? WHERE id=1", (old,))
    s = snapshot_from_context(sample_ctx, sample_now)
    view = _overview(s)
    assert {tile.label: tile.value for tile in view["tiles"]} == {
        "New reports": 7, "High-priority stories": 2, "Hunts drafted": 4, "New qualified IOCs": 7,
    }
    assert [row.story.lead.id for row in view["key_stories"]] == [1, 2, 9]
    assert sum(c.high for c in view["customers"]) == 3  # two stories, three customer matches
    assert next(row for row in view["heat"] if row.theme.id == "edge").cells[0].count == 1


def test_reports_offer_customer_priority_theme_and_text_filters(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    text = (root / "reports.html").read_text()
    assert parse(root / "reports.html").story_ids == ["story-1", "story-2", "story-7", "story-9", "story-6"]
    for name in ("customer", "priority", "theme", "q"):
        assert f'name="{name}"' in text
    assert 'data-match="law-firm|0|edge' in text
    assert "3 related reports" in text
    assert "Legal sector attacked through a remote-access gateway" in text


def test_hunts_group_by_the_theme_of_the_matched_pirs(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    text = (sample_ctx.output_dir / "dashboard/hunts.html").read_text()
    # Theme order is identity, edge, then ransomware. All five stored hunts are included.
    assert text.index('id="theme-identity"') < text.index('id="theme-edge"') < text.index('id="theme-ransomware"')
    for id_ in range(1, 6):
        assert f'href="hunts/{id_}.html"' in text
    assert 'data-filters="hunt-groups"' in text and 'name="customer"' in text
    assert "Missing tables" not in text and "invalid" not in text.lower()


def test_iocs_default_to_qualified_with_toggle_data_for_scraped_and_flags(sample_ctx, sample_now):
    # One unflagged body mention, two flagged values, seven qualified IOCs.
    sample_ctx.db.execute("UPDATE document_indicators SET context='body' WHERE indicator_id=2")
    generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    iocs = (root / "iocs.html").read_text()
    rows = parse(root / "iocs.html").rows["ioc-table"][1:]
    assert len(rows) == 10
    assert sum("hidden" not in r for r in rows) == 7
    assert sum(r["data-status"] == "scraped" and "hidden" in r for r in rows) == 1
    assert sum(r["data-status"] == "flagged" and "hidden" in r for r in rows) == 2
    assert "Include scraped" in iocs and "Include flagged" in iocs
    assert "MISP list: Public DNS resolvers" in iocs
    assert "198[.]51[.]100[.]42" in iocs
    assert "hxxps://updates-example[.]net/stage.ps1" in iocs
    assert "CVE-2026-12345" not in iocs
    assert len(parse(root / "cves.html").rows["cve-table"]) == 3
    doc = (root / "documents/1.html").read_text()
    assert "Show scraped and flagged" in doc
    assert 'data-status="flagged" hidden' in doc
    assert 'href="documents/1.html"' in iocs and "+1 more" in iocs


def test_customer_page_shows_profile_priorities_stories_and_hunts(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    page = sample_ctx.output_dir / "dashboard/profiles/law-firm.html"
    parser = parse(page)
    text = page.read_text()
    for heading in ("Who they are", "Priorities", "Technologies", "Crown jewels", "Key stories", "Hunts"):
        assert heading in text
    assert "Edge device exploitation" in text
    assert "Citrix" in text and "Internet facing" in text
    assert parser.story_ids[:2] == ["story-1", "story-7"]
    assert "../documents/9.html" in parser.collapsed_links
    assert "retention" not in text.lower() and "telemetry coverage" not in text.lower()


def test_hunt_page_puts_queries_first_and_omits_validation_ui(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    text = (sample_ctx.output_dir / "dashboard/hunts/1.html").read_text()
    for label in ("Hypothesis", "Why this customer", "Queries", "Copy KQL", "Evidence", "ATT&amp;CK techniques", "Pyramid of Pain"):
        assert label in text
    assert text.index("Web-server child process investigation") < text.index("IOC network sweep") < text.index("Evidence <")
    assert "This sentence is not present in the source report." not in text
    assert "Benign explanations" in text and "Pivots" in text
    assert "Are actors exploiting our remote-access edge?" in text
    assert "schema_valid" not in text and "Missing tables" not in text and "invalid" not in text.lower()
    # Act and Knowledge are absent when they hold nothing.
    sample_ctx.db.execute("UPDATE hunts SET package_json=json_set(package_json, '$.act', json('{}'), '$.knowledge', json('[]')) WHERE id=1")
    generate(sample_ctx, now=sample_now)
    text = (sample_ctx.output_dir / "dashboard/hunts/1.html").read_text()
    assert 'id="act"' not in text and 'id="knowledge"' not in text


def test_attack_tree_is_tactic_then_technique_then_report(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    page = sample_ctx.output_dir / "dashboard/attack.html"
    text = page.read_text()
    assert "Trending techniques" in text
    assert "Initial Access" in text and "Credential Access" in text
    assert "T1999" not in text
    assert "documents/1.html" in parse(page).tree_links
    assert re.search(r"<summary>Initial Access.*?<details>\s*<summary><code>T1190</code>.*?documents/1.html", text, re.S)
    for old in ("Stated / inferred", "ID mentions", "Quotes found"):
        assert old not in text
    assert 'href="hunts/1.html"' in text


def test_attacker_text_is_escaped_in_html(sample_ctx, sample_now):
    sample_ctx.db.execute("UPDATE documents SET url='javascript:alert(1)' WHERE id=6")
    sample_ctx.db.execute("UPDATE source_fetches SET error='<img src=x onerror=alert(1)>' WHERE status='error'")
    generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    doc = (root / "documents/6.html").read_text()
    assert "&lt;script&gt;alert(&#34;title&#34;)&lt;/script&gt;" in doc
    assert '<script>alert("title")</script>' not in doc
    assert 'href="javascript:' not in doc
    pipeline = (root / "pipeline.html").read_text()
    assert "&lt;img src=x onerror=alert(1)&gt;" in pipeline
    assert "<img src=x" not in pipeline


def test_shell_is_shared_with_live_investigations_and_scheduled_in_london(empty_ctx, sample_now):
    env, common = page_shell(empty_ctx, sample_now)
    assert "s" not in common
    assert any(item[0] == "investigate.html" for _, items in common["nav"] for item in items)
    assert "truncate_text" in env.filters
    assert next_run(datetime(2026, 10, 6, 6, 59, tzinfo=UTC)).hour == 8
    assert next_run(datetime(2026, 10, 6, 7, 0, tzinfo=UTC)).hour == 20
    # The same local hours apply after the clocks change.
    assert next_run(datetime(2026, 10, 26, 7, 59, tzinfo=UTC)).hour == 8


def test_empty_dashboard_and_stage_fallback(empty_ctx, sample_now):
    stats = generate(empty_ctx, now=sample_now)
    assert stats["pages"] == 11
    root = empty_ctx.output_dir / "dashboard"
    for page in ["index.html", "reports.html", "hunts.html", "iocs.html", "cves.html", "attack.html", "pipeline.html", "profiles/law-firm.html"]:
        assert 'class="empty"' in (root / page).read_text()
    empty_ctx.db.execute("INSERT INTO runs(id,started_at,finished_at,status,stages_json) VALUES(1,?,?, 'ok',?)", (sample_now.isoformat(), sample_now.isoformat(), '{"collect":{"status":"ok","items_new":3}}'))
    empty_ctx.db.execute("INSERT INTO runs(id,started_at,status) VALUES(2,?, 'running')", (sample_now.isoformat(),))
    generate(empty_ctx, now=sample_now)
    pipeline = (root / "pipeline.html").read_text()
    assert "run #1" in pipeline and "items new 3" in pipeline
