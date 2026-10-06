import json
import threading
from pathlib import Path

from tipipeline.attack import Attack, Technique
from tipipeline.config import load_profiles, load_table_schemas, load_themes
from tipipeline.db import connect, dumps, init_db, now_iso, upsert_indicator
from tipipeline.hunt import run
from tipipeline.hunt.draft import ReportInput, draft_hunt, hunt_indicators
from tipipeline.llm import FakeBackend
from tipipeline.models import AnalysisValidation, HuntPackage, ReportAnalysis, Settings
from tipipeline.pipeline import Context

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = load_table_schemas(ROOT)
THEMES = load_themes(ROOT)
PROFILES = load_profiles(ROOT, THEMES)
ANALYSIS = {
    'summary': 'A fictional report describes PowerShell execution and mailbox persistence.',
    'report_type': 'threat_research', 'huntable': True, 'huntable_reason': 'Observable execution and mailbox behaviours.',
    'threat_actors': [], 'malware': [], 'tools': ['PowerShell'], 'affected_technologies': [], 'cves': [],
    'targeted_sectors': ['legal services'], 'targeted_regions': ['United Kingdom'],
    'attack_steps': [
        {'order': 1, 'description': 'Execute PowerShell.', 'tactic': 'Execution', 'technique_id': 'T1059.001',
         'technique_name': 'incorrect draft name', 'basis': 'stated', 'evidence_quote': 'The actor used encoded PowerShell.',
         'observables': ['powershell.exe -EncodedCommand']},
        {'order': 2, 'description': 'Create a forwarding rule.', 'tactic': 'Persistence', 'technique_id': 'T9999',
         'technique_name': 'invalid technique', 'basis': 'inferred', 'evidence_quote': 'A forwarding rule may have been used.',
         'observables': ['New-InboxRule']},
    ],
}
VALIDATION = {
    'steps': [{'order': 1, 'technique_valid': True, 'official_technique_name': 'PowerShell', 'quote_verified': True},
              {'order': 2, 'technique_valid': False, 'official_technique_name': None, 'quote_verified': False}],
    'technology_quotes_verified': [], 'quotes_total': 2, 'quotes_verified': 1, 'invalid_techniques': ['T9999'],
}


def query(table='DeviceProcessEvents', column='DeviceName', title=None):
    return {
        'title': title or f'Behaviour in {table}', 'purpose': 'Find behaviour for analyst review.',
        'tables': [table], 'technique_ids': ['T1059.001', 'T9999'],
        'kql': f'let lookback = 14d;\n{table} | where TimeGenerated >= ago(lookback) | project TimeGenerated, {column}',
        'benign_explanations': ['Authorised administrator automation.'], 'pivots': ['Review the user and nearby activity.'],
    }


def draft(*queries):
    return {
        'title': 'Test a source-supported execution hypothesis',
        'hypothesis': 'An actor executed encoded PowerShell on monitored endpoints.',
        'scope': 'IT endpoints and related identity activity.', 'pyramid_levels': ['ttps', 'tools'],
        'queries': list(queries) or [query()],
    }


def context(tmp_path, profiles=None, response=None, settings=None):
    conn = connect(tmp_path / 't.db')
    init_db(conn)
    backend = FakeBackend({'hunt': lambda prompt: response or draft()})
    ctx = Context(root=tmp_path, settings=settings or Settings(), sources=[], profiles=profiles or PROFILES,
                  db=conn, llm=backend, themes=THEMES)
    ctx.__dict__['table_schemas'] = SCHEMAS
    ctx.__dict__['attack'] = Attack({'T1059.001': Technique('T1059.001', 'PowerShell', ('Execution',), 'https://attack.mitre.org/techniques/T1059/001/', False)})
    return ctx


def rationale(profile):
    return f'{profile.id}: the NetScaler item is why this matters.'


def seed(ctx, *, priority='high', score=90, cluster=None, huntable=1, url_suffix='1', priorities=None):
    now = now_iso()
    doc_id = ctx.db.execute(
        '''INSERT INTO documents (source_id, kind, tier, url, canonical_url, title, collected_at,
               updated_at, content_hash, text, cluster_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        ('example', 'article', 'research', f'https://example.org/{url_suffix}', f'https://example.org/{url_suffix}',
         'Fictional source report', now, now, 'hash-' + url_suffix, 'The actor used encoded PowerShell.', cluster),
    ).lastrowid
    ctx.db.execute(
        '''INSERT INTO analyses (document_id, document_version, status, model, created_at, summary, huntable, analysis_json, validation_json)
           VALUES (?, 1, 'ok', 'fake', ?, ?, ?, ?, ?)''',
        (doc_id, now, ANALYSIS['summary'], huntable, dumps(ANALYSIS), dumps(VALIDATION)),
    )
    for p in ctx.profiles:
        ctx.db.execute(
            '''INSERT INTO relevance (document_id, profile_id, document_version, priority, score, rationale,
                   matched_pirs_json, matched_technologies_json, method, created_at)
               VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'llm', ?)''',
            (doc_id, p.id, (priorities or {}).get(p.id, priority), score, rationale(p), dumps([p.pirs[0].id]),
             dumps(['Citrix NetScaler']), now),
        )
    ctx.db.commit()
    return doc_id


def add_ioc(ctx, doc_id, type_, value, warninglist=None, context_='ioc_section'):
    iid = upsert_indicator(ctx.db, type_, value, now_iso())
    ctx.db.execute('INSERT INTO document_indicators(document_id, indicator_id, context, warninglist) VALUES (?, ?, ?, ?)',
                   (doc_id, iid, context_, warninglist))
    ctx.db.commit()


def packages(ctx):
    return [HuntPackage.model_validate_json(r['package_json']) for r in ctx.db.execute('SELECT * FROM hunts ORDER BY profile_id')]


def prompts(ctx, task='hunt'):
    return [prompt for name, prompt in ctx.llm.prompts if name == task]


def test_one_llm_call_per_customer_pair_on_worker_threads(tmp_path):
    worker_ids = []
    ctx = context(tmp_path)
    ctx.llm.responders['hunt'] = lambda prompt: (worker_ids.append(threading.get_ident()) or draft())
    doc = seed(ctx)
    stats = run(ctx)
    assert stats['candidate_pairs'] == stats['hunts'] == 3
    assert stats['queries'] == 3
    assert stats['queries_dropped'] == stats['repairs'] == stats['errors'] == 0
    assert len(prompts(ctx)) == 3
    assert worker_ids and threading.get_ident() not in worker_ids
    for package in packages(ctx):
        assert package.document_id == doc
        assert package.status == 'prepared'
        assert package.framework == 'PEAK'
        assert package.execute.status == 'not_run'
        assert package.act.outcome == 'pending'
        assert package.prepare.trigger.url == 'https://example.org/1'
        assert package.prepare.priority == 'high'
        assert len(package.prepare.matched_pirs) == 1
        assert [t.name for t in package.prepare.techniques] == ['PowerShell']
        # Evidence follows the techniques the hunt tests.
        assert [e.verified for e in package.prepare.evidence] == [True]
    # Each prompt carries one customer and that customer's reason.
    for profile in PROFILES:
        mine = [p for p in prompts(ctx) if rationale(profile) in p]
        assert len(mine) == 1
        assert profile.name in mine[0]
        assert all(other.name not in mine[0] for other in PROFILES if other.id != profile.id)


def test_prompt_carries_customer_why_analysis_and_full_catalogue(tmp_path):
    law = next(p for p in PROFILES if p.id == 'law-firm')
    ctx = context(tmp_path, [law])
    seed(ctx)
    run(ctx)
    prompt = prompts(ctx)[0]
    theme = next(t.name for t in THEMES if t.id == law.pirs[0].theme)
    for expected in [law.name, law.sector, law.description, rationale(law), 'Citrix NetScaler', theme,
                     law.technologies[0].product, law.crown_jewels[0], 'quote_verified', 'powershell.exe -EncodedCommand',
                     'let lookback = 30d;']:
        assert expected in prompt
    for table, columns in SCHEMAS.items():
        assert f'{table}: {", ".join(columns)}' in prompt


def test_only_high_and_medium_pairs_are_hunted(tmp_path):
    ctx = context(tmp_path)
    seed(ctx, priorities={'law-firm': 'high', 'retail-bank': 'low', 'manufacturer-ot': 'medium'})
    stats = run(ctx)
    assert stats['candidate_pairs'] == stats['hunts'] == 2
    assert {p.profile_id for p in packages(ctx)} == {'law-firm', 'manufacturer-ot'}


def test_appliance_tables_are_valid_for_every_customer(tmp_path):
    response = draft(
        query('CommonSecurityLog', 'DeviceVendor, DeviceProduct, SourceIP'),
        query('Syslog', 'Computer, ProcessName, SyslogMessage'),
    )
    ctx = context(tmp_path, response=response)
    seed(ctx)
    stats = run(ctx)
    assert stats['hunts'] == 3
    assert stats['repairs'] == stats['queries_dropped'] == 0
    assert not prompts(ctx, 'hunt_repair')
    rows = list(ctx.db.execute('SELECT h.profile_id, q.tables_json, q.validation_status FROM queries q JOIN hunts h ON h.id = q.hunt_id'))
    assert len(rows) == 6
    assert {r['validation_status'] for r in rows} == {'schema_valid'}
    assert {json.loads(r['tables_json'])[0] for r in rows if r['profile_id'] == 'manufacturer-ot'} == {'CommonSecurityLog', 'Syslog'}


def test_failing_query_gets_one_repair_call(tmp_path):
    law = next(p for p in PROFILES if p.id == 'law-firm')
    ctx = context(tmp_path, [law], draft(query(column='DeviceNmae', title='Encoded PowerShell')))
    ctx.llm.responders['hunt_repair'] = lambda prompt: {'queries': [query(title='Encoded PowerShell')]}
    seed(ctx)
    stats = run(ctx)
    assert stats['repairs'] == 1
    assert stats['queries'] == 1
    assert stats['queries_dropped'] == 0
    repair = prompts(ctx, 'hunt_repair')
    assert len(repair) == 1 and 'DeviceNmae' in repair[0]
    row = ctx.db.execute('SELECT kql, validation_status FROM queries').fetchone()
    assert row['validation_status'] == 'schema_valid'
    assert 'DeviceNmae' not in row['kql']
    assert row['kql'].startswith('let lookback = 30d;')


def test_query_still_failing_after_repair_is_dropped(tmp_path):
    law = next(p for p in PROFILES if p.id == 'law-firm')
    bad = query('ImaginaryTable', title='Imaginary appliance table')
    ctx = context(tmp_path, [law], draft(query(), bad))
    ctx.llm.responders['hunt_repair'] = lambda prompt: {'queries': [bad]}
    seed(ctx)
    stats = run(ctx)
    assert stats['repairs'] == 1
    assert stats['queries'] == 1
    assert stats['queries_dropped'] == 1
    assert len(prompts(ctx, 'hunt_repair')) == 1
    rows = list(ctx.db.execute('SELECT title, validation_status FROM queries'))
    assert [r['title'] for r in rows] == ['Behaviour in DeviceProcessEvents']
    assert any('Imaginary appliance table' in gap for gap in packages(ctx)[0].act.gaps)


def test_failed_repair_call_drops_bad_queries_but_keeps_valid_ones(tmp_path):
    law = next(p for p in PROFILES if p.id == 'law-firm')
    ctx = context(tmp_path, [law], draft(query(), query(column='DeviceNmae')))
    seed(ctx)
    stats = run(ctx)
    assert stats['hunts'] == 1
    assert stats['errors'] == 0
    assert stats['queries'] == 1
    assert stats['queries_dropped'] == 1
    assert packages(ctx)[0].status == 'prepared'
    assert ctx.db.execute('SELECT count(*) FROM queries').fetchone()[0] == 1


def test_all_invalid_queries_without_iocs_leave_pair_retryable(tmp_path):
    law = next(p for p in PROFILES if p.id == 'law-firm')
    bad = query(column='DeviceNmae')
    ctx = context(tmp_path, [law], draft(bad))
    ctx.llm.responders['hunt_repair'] = lambda prompt: {'queries': [bad]}
    seed(ctx)
    stats = run(ctx)
    assert stats['status'] == 'error'
    assert stats['errors'] == stats['repairs'] == stats['queries_dropped'] == 1
    assert stats['hunts'] == stats['queries'] == 0
    assert packages(ctx) == []
    assert ctx.db.execute('SELECT count(*) FROM queries').fetchone()[0] == 0
    ctx.llm.responders['hunt'] = lambda prompt: draft()
    retried = run(ctx)
    assert retried['candidate_pairs'] == retried['hunts'] == retried['queries'] == 1
    assert retried['errors'] == 0

def test_ioc_sweeps_use_qualified_indicators_across_all_tables(tmp_path):
    manufacturer = next(p for p in PROFILES if p.id == 'manufacturer-ot')
    ctx = context(tmp_path, [manufacturer])
    doc = seed(ctx)
    add_ioc(ctx, doc, 'ipv4', '203.0.113.7')
    add_ioc(ctx, doc, 'sha256', 'a' * 64, context_='feed')
    add_ioc(ctx, doc, 'domain', 'scraped.example', context_='body')
    add_ioc(ctx, doc, 'domain', 'microsoft.com', 'Top domains')
    add_ioc(ctx, doc, 'domain', 'publisher.example', 'publisher')
    add_ioc(ctx, doc, 'cve', 'CVE-2026-12345')
    run(ctx)
    package = packages(ctx)[0]
    assert {'ip_addresses', 'hash_values'} <= set(package.prepare.pyramid_levels)
    sweeps = list(ctx.db.execute("SELECT * FROM queries WHERE kind='ioc_sweep'"))
    assert len(sweeps) == 2
    assert all(q['generated_by'] == 'template' and q['validation_status'] == 'schema_valid' for q in sweeps)
    ip = next(q for q in sweeps if '203.0.113.7' in q['kql'])
    # Not limited to tables a customer was thought to collect.
    assert {'CommonSecurityLog', 'SigninLogs', 'DeviceNetworkEvents', 'EmailEvents'} <= set(json.loads(ip['tables_json']))
    assert 'union isfuzzy=true' in ip['kql']
    text = ' '.join(q['kql'] for q in sweeps)
    for excluded in ('scraped.example', 'microsoft.com', 'publisher.example', 'CVE-2026-12345'):
        assert excluded not in text


def test_scraped_indicators_are_swept_only_when_enabled(tmp_path):
    ctx = context(tmp_path)
    doc = seed(ctx)
    add_ioc(ctx, doc, 'domain', 'scraped.example', context_='body')
    add_ioc(ctx, doc, 'domain', 'benign.example', 'allowlist', context_='body')
    add_ioc(ctx, doc, 'ipv4', '198.51.100.1', context_='metadata')
    assert hunt_indicators(ctx.db, [doc], include_scraped=False) == []
    scraped = hunt_indicators(ctx.db, [doc], include_scraped=True)
    assert [(i['type'], i['value']) for i in scraped] == [('domain', 'scraped.example')]
    ctx.settings = Settings(hunt={'include_scraped_iocs': True})
    run(ctx)
    sweeps = list(ctx.db.execute("SELECT kql FROM queries WHERE kind='ioc_sweep'"))
    assert len(sweeps) == 3
    assert all('scraped.example' in q['kql'] and 'benign.example' not in q['kql'] for q in sweeps)


def test_configured_lookback_applies_to_behavioural_and_sweep_queries(tmp_path):
    ctx = context(tmp_path, settings=Settings(hunt={'lookback_days': 7}))
    doc = seed(ctx)
    add_ioc(ctx, doc, 'ipv4', '203.0.113.7')
    run(ctx)
    rows = list(ctx.db.execute('SELECT kind, kql FROM queries'))
    assert {r['kind'] for r in rows} == {'behavioural', 'ioc_sweep'}
    assert all(r['kql'].startswith('let lookback = 7d;') for r in rows)
    assert all('let lookback = 7d;' in p for p in prompts(ctx))


def test_manual_draft_without_customer_or_reports(tmp_path):
    ctx = context(tmp_path)
    indicators = [{'type': 'ipv4', 'value': '203.0.113.9'}, {'type': 'cve', 'value': 'CVE-2026-1'}]
    result = draft_hunt(ctx, focus='Investigate exploitation of the gateway CVE.', reports=[], indicators=indicators)
    assert [q.kind for q in result.queries] == ['behavioural', 'ioc_sweep']
    assert all(q.validation.status == 'schema_valid' for q in result.queries)
    assert result.title and result.hypothesis and result.scope
    assert result.evidence == [] and result.dropped == 0 and not result.repaired
    prompt = prompts(ctx)[0]
    assert 'Investigate exploitation of the gateway CVE.' in prompt
    assert all(p.name not in prompt for p in PROFILES)
    assert ctx.db.execute('SELECT count(*) FROM hunts').fetchone()[0] == 0


def test_manual_draft_with_several_reports_and_a_customer(tmp_path):
    ctx = context(tmp_path)
    law = next(p for p in PROFILES if p.id == 'law-firm')
    reports = [
        ReportInput({'id': i, 'title': f'Report {i}', 'url': f'https://example.org/{i}', 'source_id': 'example', 'published_at': None},
                    ReportAnalysis.model_validate(ANALYSIS), AnalysisValidation.model_validate(VALIDATION))
        for i in (1, 2)
    ]
    result = draft_hunt(ctx, focus='Check the gateway story.', reports=reports, indicators=[], profile=law)
    assert [t.id for t in result.techniques] == ['T1059.001']
    assert len(result.evidence) == 2
    prompt = prompts(ctx)[0]
    assert law.name in prompt and 'https://example.org/2' in prompt


def test_rerun_is_idempotent_and_new_version_replaces_old_queries(tmp_path):
    ctx = context(tmp_path)
    doc = seed(ctx)
    first = run(ctx)
    old_hunt_ids = [r['id'] for r in ctx.db.execute('SELECT id FROM hunts')]
    assert first['queries'] == 3
    second = run(ctx)
    assert second['candidate_pairs'] == second['hunts'] == 0
    assert len(prompts(ctx)) == 3
    ctx.db.execute('UPDATE documents SET version=2 WHERE id=?', (doc,))
    ctx.db.execute('UPDATE analyses SET document_version=2 WHERE document_id=?', (doc,))
    ctx.db.execute('UPDATE relevance SET document_version=2 WHERE document_id=?', (doc,))
    fresh = draft(query('DeviceFileEvents', 'FileName'))
    ctx.llm.responders['hunt'] = lambda prompt: fresh
    result = run(ctx)
    assert result['queries'] == 3
    assert len(prompts(ctx)) == 6
    assert [r['id'] for r in ctx.db.execute('SELECT id FROM hunts')] == old_hunt_ids
    assert {r['document_version'] for r in ctx.db.execute('SELECT document_version FROM hunts')} == {2}
    rows = list(ctx.db.execute('SELECT * FROM queries'))
    assert len(rows) == 3
    assert all('DeviceFileEvents' in r['kql'] and 'DeviceProcessEvents' not in r['kql'] for r in rows)


def test_llm_disabled_skips_without_blocking_later_draft(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    ctx.llm_enabled = False
    result = run(ctx)
    assert result['skipped'] == 'llm disabled'
    assert result['hunts'] == 0
    assert not ctx.llm.prompts
    ctx.llm_enabled = True
    assert run(ctx)['hunts'] == 3


def test_pair_limit_prioritises_high_score_and_defers_rest(tmp_path):
    ctx = context(tmp_path)
    low = seed(ctx, score=40, url_suffix='low')
    high = seed(ctx, score=95, url_suffix='high')
    ctx.llm_limit = 3
    stats = run(ctx)
    assert stats['candidate_pairs'] == 6
    assert stats['deferred_pairs'] == 3
    assert stats['hunts'] == 3
    assert {r['document_id'] for r in ctx.db.execute('SELECT document_id FROM hunts')} == {high}
    assert low != high


def test_zero_limit_defers_everything_without_calls(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    ctx.llm_limit = 0
    result = run(ctx)
    assert result['deferred_pairs'] == 3
    assert result['hunts'] == 0
    assert ctx.llm.prompts == []


def test_stale_analysis_or_relevance_is_not_drafted(tmp_path):
    ctx = context(tmp_path)
    doc = seed(ctx)
    ctx.db.execute('UPDATE documents SET version=2 WHERE id=?', (doc,))
    assert run(ctx)['candidate_pairs'] == 0
    ctx.db.execute('UPDATE analyses SET document_version=2 WHERE document_id=?', (doc,))
    assert run(ctx)['candidate_pairs'] == 0
    assert not ctx.llm.prompts


def test_low_priority_and_nonhuntable_are_not_candidates(tmp_path):
    ctx = context(tmp_path)
    seed(ctx, priority='low')
    seed(ctx, huntable=0, url_suffix='other')
    assert run(ctx)['candidate_pairs'] == 0
    assert not ctx.llm.prompts


def test_llm_failure_is_retryable_without_empty_packages(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    ctx.llm.responders.clear()
    result = run(ctx)
    assert result['errors'] == 3
    assert result['status'] == 'error'
    assert result['hunts'] == 0
    assert ctx.db.execute('SELECT count(*) FROM hunts').fetchone()[0] == 0
    ctx.llm.responders['hunt'] = lambda prompt: draft()
    assert run(ctx)['hunts'] == 3


def test_cluster_knowledge_refers_to_related_documents_and_earlier_hunts(tmp_path):
    ctx = context(tmp_path)
    first = seed(ctx, cluster=42)
    run(ctx)
    second = seed(ctx, cluster=42, url_suffix='related')
    run(ctx)
    rows = ctx.db.execute('SELECT profile_id, package_json FROM hunts WHERE document_id=?', (second,)).fetchall()
    assert rows
    for row in rows:
        package = HuntPackage.model_validate_json(row['package_json'])
        assert len(package.knowledge) == 2
        related, earlier_hunt = package.knowledge
        assert f'[{first}]' in related
        first_hunt = ctx.db.execute('SELECT id FROM hunts WHERE document_id=? AND profile_id=?', (first, row['profile_id'])).fetchone()['id']
        assert f'#{first_hunt} ' in earlier_hunt


def test_stored_schema_metadata_is_json_serialisable(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    json.dumps(run(ctx))
    stored = ctx.db.execute('SELECT * FROM queries LIMIT 1').fetchone()
    assert json.loads(stored['tables_json']) == ['DeviceProcessEvents']
    assert json.loads(stored['technique_ids_json']) == ['T1059.001']
    assert json.loads(stored['validation_json'])['status'] == 'schema_valid'
    ReportAnalysis.model_validate(ANALYSIS)


def test_mixed_llm_success_and_failure_returns_partial(tmp_path):
    ctx = context(tmp_path)
    seed(ctx, url_suffix='good')
    seed(ctx, url_suffix='bad')

    def respond(prompt):
        if 'https://example.org/bad' in prompt:
            raise ValueError('Expected document-specific drafting failure')
        return draft()

    ctx.llm.responders['hunt'] = respond
    result = run(ctx)
    assert result['status'] == 'partial'
    assert result['errors'] == 3
    assert result['hunts'] == 3
