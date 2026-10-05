import json
from datetime import UTC, datetime, timedelta

import pytest

from tipipeline.analyse import run, select_candidates
from tipipeline.analyse.prompt import DocumentHints, build_analysis_prompt, truncate_text
from tipipeline.analyse.validate import validate_analysis, verify_quote
from tipipeline.attack import Attack, Technique
from tipipeline.db import connect, init_db, now_iso, upsert_indicator
from tipipeline.llm import FakeBackend, LLMError
from tipipeline.models import Profile, ReportAnalysis, Settings
from tipipeline.pipeline import Context


def analysis_data():
    return dict(summary='Command execution', report_type='incident', huntable=True,
                huntable_reason='Endpoint behaviour', threat_actors=[], malware=[], tools=[],
                affected_technologies=[], cves=[], targeted_sectors=[], targeted_regions=[],
                attack_steps=[dict(order=8, description='Executed PowerShell', tactic='Execution',
                                   technique_id='t1059.001 ', technique_name='Wrong name', basis='stated',
                                   evidence_quote='The attacker ran PowerShell.', observables=['PowerShell'])])


def context(tmp_path):
    conn = connect(tmp_path / 't.db')
    init_db(conn)
    profile = Profile(id='legal', name='Law', sector='legal', region='UK', description='Law firm',
                      crown_jewels=[], technologies=[dict(vendor='Citrix', product='NetScaler ADC', exposure='internet_facing')],
                      telemetry=[], retention_days=30, pirs=[])
    ctx = Context(root=tmp_path, settings=Settings(), sources=[], profiles=[profile], db=conn,
                  llm=FakeBackend({'analysis': lambda _: analysis_data()}))
    ctx.__dict__['attack'] = Attack({'T1059.001': Technique('T1059.001', 'PowerShell', ('Execution',), '', False),
                                    'T9999': Technique('T9999', 'Deprecated', (), '', True)})
    return ctx


def add_document(ctx, name, *, tier='research', published=None, duplicate=None, text='The attacker ran PowerShell.'):
    stamp = now_iso()
    return ctx.db.execute('''INSERT INTO documents (source_id,kind,tier,url,canonical_url,title,published_at,
        collected_at,updated_at,content_hash,text,duplicate_of) VALUES ('test','article',?,?,?,?,?,?,?,?,?,?)''',
        (tier, name, name, name, published or stamp, stamp, stamp, name, text, duplicate)).lastrowid


@pytest.mark.parametrize(('quote', 'verified'), [
    ('THE ATTACKER’S “TOOL” — RAN. ', True),
    ("the attacker's \"tool\" -\n\t ran", True),
    ('the attacker…ran', True),
    ('the attacker ... tool ... ran', True),
    ('ran ... the attacker', False),
    ('the attacker ... missing', False),
    ('the attacker used curl', False),
    ('...', False),
    ('', False),
])
def test_quote_verification(quote, verified):
    assert verify_quote(quote, 'The attacker’s “tool” — ran.') is verified


def test_techniques_flagged_and_official_names(tmp_path):
    ctx = context(tmp_path)
    data = analysis_data()
    data['attack_steps'] += [dict(data['attack_steps'][0], order=9, technique_id='T9999'),
                            dict(data['attack_steps'][0], order=10, technique_id='T0000')]
    data['affected_technologies'] = [dict(vendor='Microsoft', product='Windows', versions='', evidence_quote='not there')]
    validation = validate_analysis(ReportAnalysis.model_validate(data), 'The attacker ran PowerShell.', ctx.attack)
    assert [s.technique_valid for s in validation.steps] == [True, False, False]
    assert validation.steps[0].official_technique_name == 'PowerShell'
    assert validation.invalid_techniques == ['T9999', 'T0000']
    assert (validation.quotes_verified, validation.quotes_total) == (3, 4)


def test_selection_cap_priority_and_age(tmp_path):
    ctx = context(tmp_path)
    old = (datetime.now(UTC) - timedelta(days=31)).isoformat()
    base = add_document(ctx, 'base')
    add_document(ctx, 'duplicate', duplicate=base)
    add_document(ctx, 'old', published=old)
    manual = add_document(ctx, 'manual', tier='manual', published=old)
    government = add_document(ctx, 'government', tier='government')
    news = add_document(ctx, 'news', tier='news')
    rich = add_document(ctx, 'rich')
    indicator = upsert_indicator(ctx.db, 'domain', 'bad.example', now_iso())
    ctx.db.execute("INSERT INTO document_indicators VALUES (?,?,'ioc_section','',NULL)", (rich, indicator))
    done = add_document(ctx, 'done')
    ctx.db.execute("INSERT INTO analyses(document_id,document_version,status,model,created_at) VALUES (?,1,'ok','fake',?)", (done, now_iso()))
    errored = add_document(ctx, 'retry')
    ctx.db.execute("INSERT INTO analyses(document_id,document_version,status,model,created_at) VALUES (?,1,'error','fake',?)", (errored, now_iso()))
    ids = [d['id'] for d in select_candidates(ctx)]
    assert ids[0:2] == [manual, rich]
    assert set(ids) == {base, manual, government, news, rich, errored}
    assert ids.index(government) < ids.index(news)
    ctx.llm_limit = 2
    result = run(ctx)
    assert result['selected'] == result['analysed'] == 2
    assert {r[0] for r in ctx.db.execute("SELECT document_id FROM analyses WHERE status='ok'")} == {manual, rich, done}


def test_selection_cves_technology_and_recency(tmp_path):
    ctx = context(tmp_path)
    yesterday = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    old = add_document(ctx, 'yesterday', published=yesterday)
    recent = add_document(ctx, 'recent')
    tech = add_document(ctx, 'technology', published=yesterday, text='Citrix ADC ransomware')
    cve_document = add_document(ctx, 'cve', published=yesterday)
    cve = upsert_indicator(ctx.db, 'cve', 'CVE-2026-1234', now_iso())
    ctx.db.execute("INSERT INTO document_indicators VALUES (?,?,'body','',NULL)", (cve_document, cve))
    assert [d['id'] for d in select_candidates(ctx)] == [cve_document, tech, recent, old]


def test_stage_storage_idempotence_versions_errors_disabled(tmp_path):
    ctx = context(tmp_path)
    document = add_document(ctx, 'one')
    ctx.db.execute("INSERT INTO document_techniques(document_id,technique_id,source) VALUES (?,'T1059.001','explicit')", (document,))
    result = run(ctx)
    assert result['quote_verification_rate'] == 1.0
    assert result['invalid_technique_count'] == 0
    assert 'T1059.001 | PowerShell | Execution' in ctx.llm.prompts[0][1]
    assert 'T9999 | Deprecated' not in ctx.llm.prompts[0][1]
    row = ctx.db.execute('SELECT * FROM analyses').fetchone()
    assert row['status'] == 'ok' and row['document_version'] == 1
    stored = json.loads(row['analysis_json'])
    assert stored['attack_steps'][0]['order'] == 1
    assert stored['attack_steps'][0]['technique_id'] == 'T1059.001'
    technique = ctx.db.execute("SELECT * FROM document_techniques WHERE source='llm'").fetchone()
    assert technique['valid'] == technique['quote_verified'] == 1
    assert run(ctx)['selected'] == 0
    ctx.db.execute('UPDATE documents SET version=2')
    def fail(_):
        raise LLMError('backend unavailable')
    ctx.llm = FakeBackend({'analysis': fail})
    failed = run(ctx)
    assert failed['errors'] == 1 and failed['status'] == 'error'
    row = ctx.db.execute('SELECT * FROM analyses').fetchone()
    assert row['status'] == 'error' and row['document_version'] == 2
    assert 'backend unavailable' in row['error']
    assert ctx.db.execute("SELECT COUNT(*) FROM document_techniques WHERE source='llm'").fetchone()[0] == 0
    assert ctx.db.execute("SELECT COUNT(*) FROM document_techniques WHERE source='explicit'").fetchone()[0] == 1
    ctx.llm = FakeBackend({'analysis': lambda _: analysis_data()})
    assert run(ctx)['analysed'] == 1
    ctx.llm_enabled = False
    ctx.db.execute('UPDATE documents SET version=3')
    calls_before = len(ctx.llm.prompts)
    assert run(ctx)['selected'] == 0
    assert len(ctx.llm.prompts) == calls_before


def test_prompt_tail_and_metadata():
    text = 'a' * 70000 + '\nIndicators of Compromise\nsha256 abc\n'
    truncated, omitted = truncate_text(text)
    assert len(truncated) <= 60000 and omitted > 0
    assert 'sha256 abc' in truncated
    prompt = build_analysis_prompt(title='Report', source='Research', url='https://example.org',
                                  published_at=None, text=text, hints=DocumentHints(cves=['CVE-2026-1234']))
    assert 'CVE-2026-1234' in prompt and '<<<DOCUMENT_TEXT_START>>>' in prompt
    assert 'copied verbatim' in prompt and 'Published: unknown' in prompt


def test_invalid_step_is_retained_and_flagged(tmp_path):
    ctx = context(tmp_path)
    document = add_document(ctx, 'invalid')
    data = analysis_data()
    data['attack_steps'][0].update(technique_id='T0000', evidence_quote='Fabricated evidence.')
    ctx.llm = FakeBackend({'analysis': lambda _: data})
    result = run(ctx)
    assert result['analysed'] == 1 and result['invalid_technique_count'] == 1
    assert result['quote_verification_rate'] == 0.0
    row = ctx.db.execute("SELECT * FROM document_techniques WHERE document_id=? AND source='llm'", (document,)).fetchone()
    assert row['technique_id'] == 'T0000'
    assert row['valid'] == row['quote_verified'] == 0


def test_mixed_analysis_success_and_failure_returns_partial(tmp_path):
    ctx = context(tmp_path)
    add_document(ctx, 'failed')
    add_document(ctx, 'successful')
    def respond(prompt):
        if '- Title: failed\n' in prompt:
            raise LLMError('offline')
        return analysis_data()
    ctx.llm = FakeBackend({'analysis': respond})
    result = run(ctx)
    assert result['status'] == 'partial'
    assert result['analysed'] == result['errors'] == 1
