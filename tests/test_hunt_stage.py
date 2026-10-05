import json
import threading
from pathlib import Path

from tipipeline.attack import Attack, Technique
from tipipeline.config import load_profiles, load_table_schemas
from tipipeline.db import connect, dumps, init_db, now_iso, upsert_indicator
from tipipeline.hunt import run
from tipipeline.llm import FakeBackend
from tipipeline.models import HuntPackage, ReportAnalysis, Settings
from tipipeline.pipeline import Context

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = load_table_schemas(ROOT)
PROFILES = load_profiles(ROOT)
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


def draft(table='DeviceProcessEvents', column='DeviceName'):
    return {
        'title': 'Test a source-supported execution hypothesis',
        'hypothesis': 'An actor executed encoded PowerShell on monitored endpoints.',
        'scope': 'IT endpoints and related identity activity.', 'pyramid_levels': ['ttps', 'tools'],
        'queries': [{
            'title': f'Behaviour in {table}', 'purpose': 'Find behaviour for analyst review, not a confirmed compromise.',
            'tables': [table], 'technique_ids': ['T1059.001', 'T9999'],
            'kql': f'let lookback = 14d;\n{table} | where TimeGenerated >= ago(lookback) | project TimeGenerated, {column}',
            'benign_explanations': ['Authorised administrator automation.'], 'pivots': ['Review the user and nearby activity.'],
        }],
    }


def context(tmp_path, profiles=None, response=None):
    conn = connect(tmp_path / 't.db')
    init_db(conn)
    backend = FakeBackend({'hunt': lambda prompt: response or draft()})
    ctx = Context(root=tmp_path, settings=Settings(), sources=[], profiles=profiles or PROFILES, db=conn, llm=backend)
    ctx.__dict__['table_schemas'] = SCHEMAS
    ctx.__dict__['attack'] = Attack({'T1059.001': Technique('T1059.001', 'PowerShell', ('Execution',), 'https://attack.mitre.org/techniques/T1059/001/', False)})
    return ctx


def seed(ctx, *, priority='high', score=90, cluster=None, huntable=1, url_suffix='1'):
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
            '''INSERT INTO relevance (document_id, profile_id, document_version, priority, score, rationale, matched_pirs_json, method, created_at)
               VALUES (?, ?, 1, ?, ?, ?, ?, 'llm', ?)''',
            (doc_id, p.id, priority, score, 'Relevant source-supported execution behaviour.', dumps([p.pirs[0].id]), now),
        )
    ctx.db.commit()
    return doc_id


def add_ioc(ctx, doc_id, type_, value, warninglist=None):
    iid = upsert_indicator(ctx.db, type_, value, now_iso())
    ctx.db.execute('INSERT INTO document_indicators(document_id, indicator_id, context, warninglist) VALUES (?, ?, ?, ?)',
                   (doc_id, iid, 'ioc_section', warninglist))
    ctx.db.commit()


def packages(ctx):
    return [HuntPackage.model_validate_json(r['package_json']) for r in ctx.db.execute('SELECT * FROM hunts ORDER BY profile_id')]


def test_one_llm_call_per_document_all_profiles_and_main_thread_database(tmp_path):
    worker_ids = []
    ctx = context(tmp_path)
    ctx.llm.responders['hunt'] = lambda prompt: (worker_ids.append(threading.get_ident()) or draft())
    doc = seed(ctx)
    stats = run(ctx)
    assert stats['drafted_documents'] == 1
    assert stats['hunts'] == stats['prepared'] == 3
    assert stats['queries'] == 3
    assert len(ctx.llm.prompts) == 1
    assert worker_ids and worker_ids[0] != threading.get_ident()
    for package in packages(ctx):
        assert package.document_id == doc
        assert package.framework == 'PEAK'
        assert package.hunt_type == 'hypothesis-driven'
        assert package.execute.status == 'not_run'
        assert package.act.outcome == 'pending'
        assert package.prepare.trigger.url == 'https://example.org/1'
        assert package.prepare.priority == 'high'
        assert len(package.prepare.matched_pirs) == 1
        assert package.prepare.techniques[0].name == 'PowerShell'
        assert len(package.prepare.techniques) == 1
        assert [e.verified for e in package.prepare.evidence] == [True, False]
    prompt = ctx.llm.prompts[0][1]
    assert '2-4 behaviour-based' in prompt
    assert 'ProcessCommandLine' in prompt
    assert 'quote_verified' in prompt
    assert 'IOC sweeps' in prompt


def test_missing_tables_recorded_and_no_runnable_query_is_insufficient(tmp_path):
    manufacturer = next(p for p in PROFILES if p.id == 'manufacturer-ot')
    ctx = context(tmp_path, [manufacturer], draft('EmailEvents', 'Subject'))
    seed(ctx)
    stats = run(ctx)
    assert stats['insufficient_telemetry'] == 1
    package = packages(ctx)[0]
    assert package.status == 'insufficient_telemetry'
    assert package.prepare.missing_tables == ['EmailEvents']
    assert package.prepare.available_tables == []
    assert any('Cannot test' in gap and 'EmailEvents' in gap and manufacturer.name in gap for gap in package.act.gaps)
    assert any('OT visibility' in gap for gap in package.act.gaps)
    query = ctx.db.execute('SELECT * FROM queries').fetchone()
    assert query['validation_status'] == 'invalid'
    assert query['generated_by'] == 'llm'


def test_profile_specific_validity_shared_draft(tmp_path):
    ctx = context(tmp_path, response=draft('EmailEvents', 'Subject'))
    seed(ctx)
    stats = run(ctx)
    assert stats['prepared'] == 2
    assert stats['insufficient_telemetry'] == 1
    assert len(ctx.llm.prompts) == 1
    states = {p.profile_id: p.status for p in packages(ctx)}
    assert states['manufacturer-ot'] == 'insufficient_telemetry'
    assert states['law-firm'] == states['retail-bank'] == 'prepared'


def test_ioc_sweep_can_be_runnable_despite_missing_behaviour_table(tmp_path):
    manufacturer = next(p for p in PROFILES if p.id == 'manufacturer-ot')
    ctx = context(tmp_path, [manufacturer], draft('EmailEvents', 'Subject'))
    doc = seed(ctx)
    add_ioc(ctx, doc, 'ipv4', '203.0.113.7')
    add_ioc(ctx, doc, 'domain', 'malicious.example')
    add_ioc(ctx, doc, 'sha256', 'a' * 64)
    add_ioc(ctx, doc, 'domain', 'microsoft.com', 'Top domains')
    result = run(ctx)
    assert result['prepared'] == 1
    package = packages(ctx)[0]
    assert {'ip_addresses', 'domain_names', 'hash_values'} <= set(package.prepare.pyramid_levels)
    queries = list(ctx.db.execute('SELECT * FROM queries'))
    sweeps = [q for q in queries if q['kind'] == 'ioc_sweep']
    assert len(sweeps) == 3
    assert all(q['generated_by'] == 'template' and q['validation_status'] == 'schema_valid' for q in sweeps)
    assert not any('microsoft.com' in q['kql'] for q in sweeps)
    assert any(q['validation_status'] == 'invalid' for q in queries)


def test_per_profile_lookback_rewrite(tmp_path):
    profiles = [p.model_copy(update={'retention_days': 7 if p.id == 'law-firm' else p.retention_days}) for p in PROFILES]
    ctx = context(tmp_path, profiles)
    seed(ctx)
    run(ctx)
    rows = ctx.db.execute('SELECT h.profile_id, q.kql FROM queries q JOIN hunts h ON h.id=q.hunt_id').fetchall()
    for row in rows:
        expected = next(p.retention_days for p in profiles if p.id == row['profile_id'])
        assert row['kql'].startswith(f'let lookback = {expected}d;')


def test_rerun_is_idempotent_and_new_version_replaces_old_queries(tmp_path):
    ctx = context(tmp_path)
    doc = seed(ctx)
    first = run(ctx)
    old_hunt_ids = [r['id'] for r in ctx.db.execute('SELECT id FROM hunts')]
    assert first['queries'] == 3
    second = run(ctx)
    assert second['candidate_documents'] == second['hunts'] == 0
    assert len(ctx.llm.prompts) == 1
    ctx.db.execute('UPDATE documents SET version=2 WHERE id=?', (doc,))
    ctx.db.execute('UPDATE analyses SET document_version=2 WHERE document_id=?', (doc,))
    ctx.db.execute('UPDATE relevance SET document_version=2 WHERE document_id=?', (doc,))
    fresh = draft('DeviceFileEvents', 'FileName')
    ctx.llm.responders['hunt'] = lambda prompt: fresh
    result = run(ctx)
    assert result['queries'] == 3
    assert len(ctx.llm.prompts) == 2
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


def test_document_limit_prioritises_high_score_and_defers_rest(tmp_path):
    ctx = context(tmp_path)
    low = seed(ctx, score=40, url_suffix='low')
    high = seed(ctx, score=95, url_suffix='high')
    ctx.llm_limit = 1
    stats = run(ctx)
    assert stats['candidate_documents'] == 2
    assert stats['deferred_documents'] == 1
    assert stats['drafted_documents'] == 1
    assert {r['document_id'] for r in ctx.db.execute('SELECT document_id FROM hunts')} == {high}
    assert low != high


def test_zero_limit_defers_everything_without_calls(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    ctx.llm_limit = 0
    result = run(ctx)
    assert result['deferred_documents'] == 1
    assert result['hunts'] == 0
    assert ctx.llm.prompts == []


def test_stale_analysis_or_relevance_is_not_drafted(tmp_path):
    ctx = context(tmp_path)
    doc = seed(ctx)
    ctx.db.execute('UPDATE documents SET version=2 WHERE id=?', (doc,))
    assert run(ctx)['candidate_documents'] == 0
    ctx.db.execute('UPDATE analyses SET document_version=2 WHERE document_id=?', (doc,))
    assert run(ctx)['candidate_documents'] == 0
    assert not ctx.llm.prompts


def test_low_priority_and_nonhuntable_are_not_candidates(tmp_path):
    ctx = context(tmp_path)
    seed(ctx, priority='low')
    seed(ctx, huntable=0, url_suffix='other')
    assert run(ctx)['candidate_documents'] == 0
    assert not ctx.llm.prompts


def test_llm_failure_is_retryable_without_empty_packages(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    ctx.llm.responders.clear()
    result = run(ctx)
    assert result['errors'] == 1
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
    rows = ctx.db.execute('SELECT package_json FROM hunts WHERE document_id=?', (second,)).fetchall()
    for row in rows:
        package = HuntPackage.model_validate_json(row['package_json'])
        assert any(f'[{first}]' in n and 'Related report' in n for n in package.knowledge)
        assert any('Earlier prepared hunt' in n and 'not an execution result' in n for n in package.knowledge)


def test_column_warnings_remain_prepared_but_have_manual_review_gap(tmp_path):
    ctx = context(tmp_path, response=draft(column='DeviceNmae'))
    seed(ctx)
    result = run(ctx)
    assert result['prepared'] == 3
    assert {r['validation_status'] for r in ctx.db.execute('SELECT validation_status FROM queries')} == {'warnings'}
    assert all(any('DeviceNmae' in gap for gap in p.act.gaps) for p in packages(ctx))


def test_stored_schema_metadata_is_json_serialisable(tmp_path):
    ctx = context(tmp_path)
    seed(ctx)
    json.dumps(run(ctx))
    query = ctx.db.execute('SELECT * FROM queries LIMIT 1').fetchone()
    assert json.loads(query['tables_json']) == ['DeviceProcessEvents']
    assert json.loads(query['technique_ids_json']) == ['T1059.001']
    assert json.loads(query['validation_json'])['status'] == 'schema_valid'
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
    assert result['errors'] == 1
    assert result['hunts'] == 3
    assert result['drafted_documents'] == 1
