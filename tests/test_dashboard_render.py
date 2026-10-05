from html.parser import HTMLParser
from urllib.parse import urlsplit

from tipipeline.dashboard import generate
from tipipeline.report import generate as report_generate


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.script_tags = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "script":
            self.script_tags.append(attrs)

    def handle_data(self, data):
        self.text.append(data)


def test_dashboard_renders_complete_local_site(sample_ctx, sample_now):
    report_generate(sample_ctx, now=sample_now)
    stats = generate(sample_ctx, now=sample_now)
    root = sample_ctx.output_dir / "dashboard"
    assert stats == {"pages": 21, "documents": 9, "hunts": 5, "profiles": 3}
    expected = ["index.html", "iocs.html", "attack.html", "sources.html", "style.css", "app.js", "profiles/law-firm.html", "profiles/retail-bank.html", "profiles/manufacturer-ot.html", "documents/1.html", "documents/6.html", "hunts/1.html", "hunts/3.html"]
    for name in expected:
        assert (root / name).is_file()
    for page in root.rglob("*.html"):
        parser = PageParser()
        parser.feed(page.read_text())
        for href in parser.links:
            if urlsplit(href).scheme or href.startswith("#"):
                continue
            target = page.parent / href.split("#")[0]
            assert target.exists(), f"Broken relative link: {page.name}: {href}"
        assert all(tag.get("src") and not urlsplit(tag["src"]).scheme for tag in parser.script_tags)
    hunt = (root / "hunts/1.html").read_text()
    for text in ["Prepare", "Execute", "Act", "Knowledge", "Copy KQL", "schema_valid".replace("_", " "), "not run", "Are actors exploiting our remote-access edge?", "verified", "unverified"]:
        assert text in hunt
    assert "HTTP 403" in (root / "sources.html").read_text()
    iocs = (root / "iocs.html").read_text()
    assert "198[.]51[.]100[.]42" in iocs
    assert "hxxps://updates-example[.]net/stage.ps1" in iocs
    assert "login.microsoftonline.com" not in iocs
    assert "Public DNS resolvers" in iocs
    attack = (root / "attack.html").read_text()
    for text in ["Initial Access", "Stated / inferred", "Verified step quotes", "Invalid technique IDs", "T1999"]:
        assert text in attack
    assert sample_ctx.llm.prompts == []


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
    sources = (root / "sources.html").read_text()
    assert "&lt;img src=x onerror=alert(1)&gt;" in sources
    assert "<img src=x" not in sources


def test_empty_dashboard_and_stage_fallback(empty_ctx, sample_now):
    stats = generate(empty_ctx, now=sample_now)
    assert stats["pages"] == 7
    root = empty_ctx.output_dir / "dashboard"
    index = (root / "index.html").read_text()
    assert "No pipeline runs recorded" in index
    assert "No high-priority items assessed" in index
    assert "No documents collected" in index
    assert "No indicators extracted" in (root / "iocs.html").read_text()
    assert "No valid ATT&amp;CK techniques extracted" in (root / "attack.html").read_text()
    assert "No hunt packages prepared" in (root / "profiles/law-firm.html").read_text()
    empty_ctx.db.execute("INSERT INTO runs(id,started_at,finished_at,status,stages_json) VALUES(1,?,?, 'ok',?)", (sample_now.isoformat(), sample_now.isoformat(), '{"collect":{"status":"ok"}}'))
    empty_ctx.db.execute("INSERT INTO runs(id,started_at,status) VALUES(2,?, 'running')", (sample_now.isoformat(),))
    generate(empty_ctx, now=sample_now)
    assert "Showing the last completed run (#1)" in (root / "index.html").read_text()
