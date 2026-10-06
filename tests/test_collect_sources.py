from __future__ import annotations

import html
import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from tipipeline import collect
from tipipeline.db import connect, init_db
from tipipeline.llm import FakeBackend
from tipipeline.models import Settings, SourceConfig
from tipipeline.pipeline import Context


@pytest.fixture
def ctx(tmp_path):
    db = connect(tmp_path / 'test.db')
    init_db(db)
    context = Context(root=tmp_path, settings=Settings(), sources=[], profiles=[], db=db, llm=FakeBackend())
    yield context
    db.close()


def source(kind='rss', tier='research', max_items=20):
    return SourceConfig(id=kind, name=kind, kind=kind, tier=tier, url=f'https://feed.test/{kind}', max_items=max_items)


def mock_http(monkeypatch, handler):
    client = httpx.Client
    monkeypatch.setattr(collect.httpx, 'Client', lambda **kwargs: client(transport=httpx.MockTransport(handler), **kwargs))


def rss(items):
    entries = []
    for url, title, published, content in items:
        date = f'<pubDate>{format_datetime(published)}</pubDate>' if published else ''
        entries.append(f'<item><title>{html.escape(title)}</title><link>{html.escape(url)}</link>{date}<description>{html.escape(content)}</description></item>')
    return '<rss version="2.0"><channel><title>Research</title><link>https://feed.test/</link><description>Research</description>' + ''.join(entries) + '</channel></rss>'


@pytest.mark.parametrize(('url', 'expected'), [
    ('HTTPS://EXAMPLE.COM:443/path/?utm_source=x&b=2&a=1#fragment', 'https://example.com/path?a=1&b=2'),
    ('http://EXAMPLE.COM:80/', 'http://example.com'),
    ('https://example.com/?fbclid=1&gclid=2&mc_cid=3&mc_eid=4&ref=5&source=6&ref_src=7&x=', 'https://example.com?x='),
    ('https://example.com:8443/a///?z=2&a=3&a=1', 'https://example.com:8443/a?a=1&a=3&z=2'),
    ('https://[2001:DB8::1]:443/a/', 'https://[2001:db8::1]/a'),
    ('https://example.com/a?UTM_medium=x&Source_ID=2&q=a%20b', 'https://example.com/a?q=a+b'),
    ('urn:cisa-kev:CVE-2026-1234', 'urn:cisa-kev:CVE-2026-1234'),
])
def test_canonicalization(url, expected):
    assert collect.canonicalize_url(url) == expected


def test_content_versioning_and_unchanged_noop(ctx):
    doc = collect.Document('manual', 'manual', 'article', 'https://a.test/report', 'https://a.test/report', 'Original', 'This is the original content.', meta={'one': 1})
    doc_id, status = collect._store(ctx, doc)
    assert status == 'new'
    ctx.db.execute('UPDATE documents SET processed_version=1, extracted_version=1 WHERE id=?', (doc_id,))
    first = dict(ctx.db.execute('SELECT * FROM documents').fetchone())
    doc.text = 'This   is the original\ncontent.'
    assert collect._store(ctx, doc) == (doc_id, 'unchanged')
    assert dict(ctx.db.execute('SELECT * FROM documents').fetchone()) == first
    doc.title, doc.text, doc.meta = 'Revised', 'This is a material revision of the report.', {'one': 2}
    assert collect._store(ctx, doc) == (doc_id, 'updated')
    revised = ctx.db.execute('SELECT * FROM documents').fetchone()
    assert revised['version'] == 2
    assert revised['processed_version'] == revised['extracted_version'] == 1
    assert json.loads(revised['meta_json']) == {'one': 2}
    old = ctx.db.execute('SELECT * FROM document_versions').fetchone()
    assert old['version'] == 1 and old['text'] == first['text'] and old['title'] == 'Original'
    assert old['content_hash'] == first['content_hash']
    assert ctx.db.execute('SELECT COUNT(*) FROM document_versions').fetchone()[0] == 1


def test_rss_initial_lookback_newest_cap_and_extraction_fallback(ctx, monkeypatch):
    ctx.sources = [source(tier='government', max_items=1)]
    now = datetime.now(UTC)
    feed = rss([
        ('https://article.test/old', 'Old', now - timedelta(days=30), '<p>Old report</p>'),
        ('https://article.test/undated', 'Undated', None, '<p>Undated report</p>'),
        ('https://article.test/older', 'Older', now - timedelta(days=2), '<p>Older report</p>'),
        ('https://article.test/new/?utm_source=feed', 'Newest & greatest', now - timedelta(days=1), '<p>Adversaries exploited a newly exposed service.</p><script>ignore()</script>'),
    ])
    fetched = []
    def handler(request):
        assert request.headers['User-Agent'] == ctx.settings.user_agent
        if request.url.host == 'feed.test':
            return httpx.Response(200, text=feed)
        fetched.append(str(request.url))
        return httpx.Response(503)
    mock_http(monkeypatch, handler)
    result = collect.run(ctx)
    assert result['sources_ok'] == 1 and result['items_seen'] == 4 and result['items_new'] == 1
    assert fetched == ['https://article.test/new/?utm_source=feed']
    doc = ctx.db.execute('SELECT * FROM documents').fetchone()
    assert doc['canonical_url'] == 'https://article.test/new'
    assert doc['kind'] == 'advisory' and doc['title'] == 'Newest & greatest'
    assert doc['text'] == 'Adversaries exploited a newly exposed service.'
    assert datetime.fromisoformat(doc['published_at']).utcoffset() == timedelta(0)
    assert json.loads(doc['meta_json'])['text_source'] == 'feed'


def test_rss_recollection_version_counts_and_unchanged_noop(ctx, monkeypatch):
    ctx.sources = [source()]
    stamp = datetime.now(UTC) - timedelta(hours=1)
    state = {'text': 'Original report content.', 'calls': 0}
    def handler(request):
        if request.url.host == 'feed.test':
            return httpx.Response(200, text=rss([('https://article.test/report', 'Report', stamp, state['text'])]))
        state['calls'] += 1
        return httpx.Response(200, text='<html><body><article><p>' + state['text'] + '</p></article></body></html>')
    mock_http(monkeypatch, handler)
    assert collect.run(ctx)['items_new'] == 1
    first = dict(ctx.db.execute('SELECT * FROM documents').fetchone())
    assert collect.run(ctx)['items_new'] == 0
    assert dict(ctx.db.execute('SELECT * FROM documents').fetchone()) == first
    assert state['calls'] == 1  # Identical feed signature avoids another article request.
    state['text'] = 'Revised report with a significant correction.'
    stats = collect.run(ctx)
    assert stats['items_updated'] == 1 and stats['items_new'] == 0
    assert ctx.db.execute('SELECT version FROM documents').fetchone()[0] == 2
    assert ctx.db.execute('SELECT text FROM document_versions').fetchone()[0] == 'Original report content.'
    fetches = list(ctx.db.execute('SELECT status, items_new, items_updated FROM source_fetches ORDER BY id'))
    assert [tuple(r) for r in fetches] == [('ok', 1, 0), ('ok', 0, 0), ('ok', 0, 1)]


def test_rss_title_and_date_correction_without_new_version(ctx, monkeypatch):
    ctx.sources = [source()]
    stamp = datetime.now(UTC) - timedelta(hours=2)
    state = {'title': 'Report', 'published': stamp}
    def handler(request):
        if request.url.host == 'feed.test':
            return httpx.Response(200, text=rss([('https://article.test/report', state['title'], state['published'], 'Original report content.')]))
        return httpx.Response(200, text='<html><body><article><p>Original report content.</p></article></body></html>')
    mock_http(monkeypatch, handler)
    collect.run(ctx)
    ctx.db.execute('UPDATE documents SET processed_version=1, extracted_version=1')
    state.update(title='Report (corrected)', published=stamp - timedelta(days=1))
    stats = collect.run(ctx)
    assert stats['items_new'] == stats['items_updated'] == 0
    doc = ctx.db.execute('SELECT * FROM documents').fetchone()
    assert doc['title'] == 'Report (corrected)'
    assert doc['published_at'] == (stamp - timedelta(days=1)).isoformat(timespec='seconds')
    assert doc['version'] == 1 and doc['extracted_version'] == 1
    assert doc['processed_version'] is None  # near-duplicate matching uses title and date
    assert ctx.db.execute('SELECT COUNT(*) FROM document_versions').fetchone()[0] == 0


def test_kev_filter_mapping_and_raw_metadata(ctx, monkeypatch):
    ctx.sources = [source('cisa_kev', 'government')]
    today = datetime.now(UTC).date()
    record = {'cveID': 'CVE-2026-1234', 'vendorProject': 'Example', 'product': 'Gateway', 'vulnerabilityName': 'Gateway Command Injection',
              'dateAdded': today.isoformat(), 'shortDescription': 'Remote command execution.', 'requiredAction': 'Apply vendor update.',
              'dueDate': (today + timedelta(days=21)).isoformat(), 'knownRansomwareCampaignUse': 'Known', 'notes': 'https://vendor.test/advisory', 'cwes': ['CWE-78']}
    old = {**record, 'cveID': 'CVE-2020-1234', 'dateAdded': (today - timedelta(days=31)).isoformat()}
    mock_http(monkeypatch, lambda request: httpx.Response(200, json={'vulnerabilities': [old, record]}))
    stats = collect.run(ctx)
    assert stats['items_seen'] == 2 and stats['items_new'] == 1
    doc = ctx.db.execute('SELECT * FROM documents').fetchone()
    assert doc['kind'] == 'vulnerability'
    assert doc['canonical_url'] == 'urn:cisa-kev:CVE-2026-1234'
    assert doc['url'] == 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234'
    assert doc['title'] == 'CVE-2026-1234: Gateway Command Injection'
    assert doc['published_at'] == today.isoformat() + 'T00:00:00+00:00'
    assert json.loads(doc['meta_json']) == record
    assert 'knownRansomwareCampaignUse: Known' in doc['text'] and 'requiredAction: Apply vendor update.' in doc['text']


def test_threatfox_grouping_metadata_and_sliding_window_union(ctx, monkeypatch):
    ctx.sources = [source('threatfox', 'ioc_feed')]
    monkeypatch.setenv('THREATFOX_AUTH_KEY', 'fixture-secret')
    day = datetime.now(UTC).date().isoformat()
    entry = {'ioc_type': 'ip:port', 'ioc': '203.0.113.17:443', 'threat_type': 'botnet_cc', 'confidence_level': 90,
             'malware': 'win.example', 'malware_printable': 'Example RAT', 'tags': ['C2'], 'reference': 'https://research.test/report', 'first_seen': day + ' 08:00:00 UTC'}
    entries = [entry, {**entry, 'ioc_type': 'domain', 'ioc': 'evil.example'}, {**entry, 'malware_printable': 'Other RAT', 'ioc': '203.0.113.18:443'}]
    def handler(request):
        assert request.method == 'POST'
        assert request.headers['Auth-Key'] == 'fixture-secret'
        assert json.loads(request.content) == {'query': 'get_iocs', 'days': 1}
        return httpx.Response(200, json={'query_status': 'ok', 'data': entries})
    mock_http(monkeypatch, handler)
    stats = collect.run(ctx)
    assert stats['items_seen'] == 3 and stats['items_new'] == 2
    doc = ctx.db.execute("SELECT * FROM documents WHERE canonical_url=?", (f'urn:threatfox:example-rat:{day}',)).fetchone()
    assert doc['kind'] == 'ioc_batch' and doc['title'] == f'ThreatFox: Example RAT IOCs {day}'
    meta = json.loads(doc['meta_json'])
    assert meta['malware'] == 'Example RAT' and len(meta['iocs']) == 2
    assert set(meta['iocs'][0]) == {'ioc_type', 'ioc', 'threat_type', 'confidence_level', 'malware', 'tags', 'reference', 'first_seen'}
    assert meta['iocs'][0]['confidence_level'] == 90 and meta['iocs'][0]['malware'] == 'Example RAT'
    # Later responses omit an old indicator: preserve it and add the new one.
    entries[:] = [{**entry, 'ioc': '203.0.113.19:443'}]
    stats = collect.run(ctx)
    assert stats['items_updated'] == 1
    revised = ctx.db.execute('SELECT * FROM documents WHERE id=?', (doc['id'],)).fetchone()
    assert len(json.loads(revised['meta_json'])['iocs']) == 3 and revised['version'] == 2
    assert collect.run(ctx)['items_updated'] == 0


def test_threatfox_skipped_without_key(ctx, monkeypatch):
    ctx.sources = [source('threatfox', 'ioc_feed')]
    monkeypatch.delenv('THREATFOX_AUTH_KEY', raising=False)
    mock_http(monkeypatch, lambda request: pytest.fail('skipped source must not request HTTP'))
    assert collect.run(ctx)['sources_skipped'] == 1
    row = ctx.db.execute('SELECT * FROM source_fetches').fetchone()
    assert row['status'] == 'skipped' and 'THREATFOX_AUTH_KEY' in row['error']


def test_source_failure_isolated_and_run_id_recorded(ctx, monkeypatch):
    ctx.db.execute("INSERT INTO runs (started_at) VALUES ('2026-10-05T00:00:00+00:00')")
    ctx.db.commit()
    ctx.run_id = 1
    ctx.sources = [source(), source('cisa_kev', 'government'), SourceConfig(id='disabled', name='Disabled', kind='rss', tier='news', url='https://disabled.test', enabled=False)]
    def handler(request):
        if request.url.path == '/rss':
            return httpx.Response(500)
        return httpx.Response(200, json={'vulnerabilities': []})
    mock_http(monkeypatch, handler)
    stats = collect.run(ctx)
    assert stats['sources_ok'] == stats['sources_error'] == 1
    assert stats['status'] == 'partial'
    fetches = list(ctx.db.execute('SELECT * FROM source_fetches'))
    assert len(fetches) == 2 and all(row['run_id'] == 1 for row in fetches)
    assert next(row for row in fetches if row['status'] == 'error')['error']


def test_manual_submission_extracts_title_and_versions(ctx, monkeypatch):
    monkeypatch.setattr(collect.socket, "getaddrinfo", lambda host, port, **kw: [(2, 1, 6, "", ("93.184.215.14", port))])
    state = {'body': ' '.join(f'Paragraph {i} describes the report with substantive incident detail.' for i in range(30))}
    def handler(request):
        return httpx.Response(200, text='<html><head><title>Security report</title><meta property="article:published_time" content="2026-10-01T12:00:00Z"></head><body><article><h1>Security report</h1><p>' + state['body'] + '</p></article></body></html>')
    mock_http(monkeypatch, handler)
    doc_id = collect.submit_url(ctx, 'https://research.test/report/?utm_source=mail')
    row = ctx.db.execute('SELECT * FROM documents').fetchone()
    assert row['source_id'] == row['tier'] == 'manual' and row['kind'] == 'article'
    assert row['canonical_url'] == 'https://research.test/report'
    assert row['title'] == 'Security report' and state['body'] in row['text']
    assert collect.submit_url(ctx, 'https://research.test/report') == doc_id
    state['body'] += ' New remediation detail changes the report.'
    assert collect.submit_url(ctx, 'https://research.test/report') == doc_id
    assert ctx.db.execute('SELECT version FROM documents').fetchone()[0] == 2
    with pytest.raises(ValueError, match='HTTP'):
        collect.submit_url(ctx, 'file:///etc/passwd')


@pytest.mark.parametrize('include_good', [False, True])
def test_article_failures_propagate_stage_status_and_keep_good_documents(ctx, monkeypatch, include_good):
    ctx.sources = [source()]
    stamp = datetime.now(UTC) - timedelta(hours=1)
    items = [('https://article.test/bad', 'Failed report', stamp, '')]
    if include_good:
        items.append(('https://article.test/good', 'Good report', stamp, 'Usable intelligence from the feed fallback.'))
    def handler(request):
        if request.url.host == 'feed.test':
            return httpx.Response(200, text=rss(items))
        return httpx.Response(503)
    mock_http(monkeypatch, handler)
    stats = collect.run(ctx)
    assert stats['status'] == ('partial' if include_good else 'error')
    assert stats['sources_error'] == 1
    assert stats['items_new'] == int(include_good)
    fetch = ctx.db.execute('SELECT * FROM source_fetches').fetchone()
    assert fetch['status'] == 'error' and 'https://article.test/bad' in fetch['error']
    assert ctx.db.execute('SELECT COUNT(*) FROM documents').fetchone()[0] == int(include_good)
