from html.parser import HTMLParser
from urllib.parse import urlsplit

from tipipeline.dashboard import generate
from tipipeline.report import generate as report_generate


class PageParser(HTMLParser):
    """Collects links, script tags, table rows by table id, and links inside closed <details>."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.script_tags = []
        self.rows = {}
        self.collapsed_links = []
        self.open_links = []
        self._table = None
        self._details = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
            (self.collapsed_links if any(not is_open for is_open in self._details) else self.open_links).append(attrs["href"])
        if tag == "script":
            self.script_tags.append(attrs)
        if tag == "table":
            self._table = attrs.get("id")
            self.rows.setdefault(self._table, 0)
        if tag == "tr" and self._table is not None:
            self.rows[self._table] += 1
        if tag == "details":
            self._details.append("open" in attrs)

    def handle_endtag(self, tag):
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
    assert stats == {"pages": 22, "documents": 9, "hunts": 5, "profiles": 3}
    expected = ["index.html", "iocs.html", "cves.html", "attack.html", "pipeline.html", "style.css", "app.js",
                "profiles/law-firm.html", "profiles/retail-bank.html", "profiles/manufacturer-ot.html",
                "documents/1.html", "documents/6.html", "hunts/1.html", "hunts/3.html"]
    for name in expected:
        assert (root / name).is_file()
    for page in root.rglob("*.html"):
        parser = parse(page)
        for href in parser.links:
            if urlsplit(href).scheme or href.startswith("#"):
                continue
            target = page.parent / href.split("#")[0]
            assert target.exists(), f"Broken relative link: {page.name}: {href}"
        assert all(tag.get("src") and not urlsplit(tag["src"]).scheme for tag in parser.script_tags)
    assert "HTTP 403" in (root / "pipeline.html").read_text()
    assert sample_ctx.llm.prompts == []


def test_overview_lists_each_customer_and_prepared_hunts(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    links = parse(sample_ctx.output_dir / "dashboard/index.html").links
    for profile_id in ("law-firm", "retail-bank", "manufacturer-ot"):
        assert f"profiles/{profile_id}.html" in links
    # Hunts 1 and 2 are prepared; 3 and 4 lack telemetry and 5 is informational.
    assert "hunts/1.html" in links and "hunts/2.html" in links
    assert not {"hunts/3.html", "hunts/4.html", "hunts/5.html"} & set(links)


def test_cves_are_separate_from_iocs(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    iocs = (root / "iocs.html").read_text()
    cves = (root / "cves.html").read_text()
    # 12 indicators in the fixture, 2 of them CVEs. Every row is in the HTML (JS only trims the view).
    assert parse(root / "iocs.html").rows["ioc-table"] == 1 + 10
    assert parse(root / "cves.html").rows["cve-table"] == 1 + 2
    assert "CVE-2026-12345" not in iocs and "CVE-2026-12345" in cves
    assert "198[.]51[.]100[.]42" in iocs
    assert "hxxps://updates-example[.]net/stage.ps1" in iocs
    assert "login.microsoftonline.com" not in iocs
    assert "Public DNS resolvers" in iocs


def test_customer_page_collapses_low_and_none_relevance(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    page = sample_ctx.output_dir / "dashboard/profiles/law-firm.html"
    parser = parse(page)
    # law-firm: documents 1 and 3 are high, 7 is medium, 9 is low, 8 is none.
    assert "../documents/1.html" in parser.open_links
    assert "../documents/7.html" in parser.open_links
    assert "../documents/9.html" in parser.collapsed_links
    assert "../documents/8.html" in parser.collapsed_links
    assert "../documents/8.html" not in parser.open_links
    text = page.read_text()
    assert "<li>Exact deployed versions and exposure are not confirmed.</li>" in text
    assert "confirmed.; " not in text


def test_hunt_page_shows_query_specific_validation_only(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    valid = (root / "hunts/1.html").read_text()
    invalid = (root / "hunts/2.html").read_text()
    for text in ["Prepare", "Execute", "Act", "Knowledge", "Copy KQL", "Are actors exploiting our remote-access edge?"]:
        assert text in valid
    # Queries with no messages get no messages box; the invalid query shows its own reason.
    assert 'class="checks' not in valid
    assert "<li>Unknown table: UnconfiguredProcessTable</li>" in invalid


def test_attack_page_groups_by_tactic(sample_ctx, sample_now):
    generate(sample_ctx, now=sample_now)
    attack = (sample_ctx.output_dir / "dashboard/attack.html").read_text()
    for text in ["Initial Access", "Credential Access", "T1999"]:
        assert text in attack


def test_attacker_text_is_escaped_in_html(sample_ctx, sample_now):
    # Values with dangerous URL schemes must never become active hrefs.
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


def test_empty_dashboard_and_stage_fallback(empty_ctx, sample_now):
    stats = generate(empty_ctx, now=sample_now)
    assert stats["pages"] == 8
    root = empty_ctx.output_dir / "dashboard"
    for page in ["index.html", "iocs.html", "cves.html", "attack.html", "pipeline.html", "profiles/law-firm.html"]:
        assert 'class="empty"' in (root / page).read_text()
    empty_ctx.db.execute("INSERT INTO runs(id,started_at,finished_at,status,stages_json) VALUES(1,?,?, 'ok',?)", (sample_now.isoformat(), sample_now.isoformat(), '{"collect":{"status":"ok","items_new":3}}'))
    empty_ctx.db.execute("INSERT INTO runs(id,started_at,status) VALUES(2,?, 'running')", (sample_now.isoformat(),))
    generate(empty_ctx, now=sample_now)
    pipeline = (root / "pipeline.html").read_text()
    # Run 2 has no stage results yet, so the stage table falls back to run 1.
    assert "run #1" in pipeline and "items new 3" in pipeline
