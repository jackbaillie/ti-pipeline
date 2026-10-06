import json

import pytest

from tipipeline.db import connect, dumps, init_db, now_iso
from tipipeline.llm import FakeBackend, LLMError
from tipipeline.models import AffectedTechnology, Profile, ReportAnalysis, Settings, Technology
from tipipeline.pipeline import Context
from tipipeline.relevance import run
from tipipeline.relevance.rules import assess_kev, kev_record, match_sectors, prepare_text, technology_matches, technology_mentioned


def profile(id='law', *, vendor='Citrix', product='NetScaler ADC', exposure='internet_facing'):
    return Profile(id=id, name=id, sector='legal', region='UK', description='Law firm', crown_jewels=['client files'],
                   technologies=[dict(vendor=vendor, product=product, exposure=exposure)], telemetry=[], retention_days=30,
                   pirs=[dict(id='P1', question='Ransomware targeting legal firms?', keywords=['ransomware', 'law firms'])])


def analysis():
    return ReportAnalysis(summary='Ransomware affecting law firms', report_type='campaign', huntable=True,
                          huntable_reason='Attacker behaviour', threat_actors=[], malware=[], tools=[],
                          affected_technologies=[], cves=[], targeted_sectors=['professional services'],
                          targeted_regions=['Europe'], attack_steps=[])


def context(tmp_path):
    db = connect(tmp_path / 't.db')
    init_db(db)
    return Context(root=tmp_path, settings=Settings(), sources=[], profiles=[profile(), profile('other')], db=db,
                   llm=FakeBackend())


def add_document(ctx, kind='vulnerability', meta=None):
    stamp = now_iso()
    next_id = ctx.db.execute('SELECT COALESCE(MAX(id), 0) + 1 FROM documents').fetchone()[0]
    url = f'https://example.test/report/{next_id}'
    return ctx.db.execute('''INSERT INTO documents(source_id,kind,tier,url,canonical_url,title,collected_at,
         updated_at,content_hash,text,meta_json) VALUES ('test',?,'government',?,?,?,?,?,?,?,?)''',
         (kind, url, url, 'Report', stamp, stamp, stamp, 'Ransomware law firms', dumps(meta or {}))).lastrowid


def kev(**overrides):
    return kev_record(dict(cveID='CVE-2026-1000', vendorProject='Citrix', product='NetScaler',
                          dateAdded='2026-10-01', dueDate='2026-10-20', knownRansomwareCampaignUse='Unknown', **overrides))


@pytest.mark.parametrize(('exposure', 'ransomware', 'expected'), [
    ('internet_facing', 'Unknown', 'high'), ('internal', 'Unknown', 'medium'),
    ('internal', 'Known', 'high'), ('ot', 'Known', 'high'),
])
def test_kev_priorities(exposure, ransomware, expected):
    record = kev()
    record['knownRansomwareCampaignUse'] = ransomware
    result = assess_kev(profile(exposure=exposure), record)
    assert result.priority == expected
    assert result.matched_technologies == ['Citrix NetScaler ADC']
    assert 'Deployed version' in result.unknowns[0]
    assert '2026-10-20' in result.rationale


def test_kev_no_match_vendor_mismatch_and_aliases():
    result = assess_kev(profile(vendor='Microsoft', product='Exchange Server'), kev())
    assert result.priority == 'none' and result.score == 0
    assert not technology_matches(Technology(vendor='Other', product='NetScaler ADC', exposure='internal'), 'Citrix', 'NetScaler')
    assert technology_matches(profile().technologies[0], 'Cloud Software Group', 'Citrix ADC')
    assert technology_matches(Technology(vendor='Fortinet', product='FortiGate', exposure='internet_facing'), 'Fortinet', 'FortiOS')
    assert not technology_matches(Technology(vendor='Microsoft', product='SQL Server', exposure='internal'), 'Microsoft', 'Exchange Server')
    assert not technology_matches(Technology(vendor='Microsoft', product='Exchange Online', exposure='cloud_service'), 'Microsoft', 'Exchange Server')
    record = kev(vulnerabilityName='Citrix ADC flaw', shortDescription='Impacts NetScaler ADC')
    record['product'] = 'Multiple Products'
    assert assess_kev(profile(), record).priority == 'high'
    assert technology_mentioned(Technology(vendor='Microsoft', product='Defender for Endpoint', exposure='endpoint'),
                                prepare_text('Microsoft Defender for Endpoint telemetry'))


@pytest.mark.parametrize(('sector', 'target'), [('legal', 'law firms'), ('legal', 'professional services'),
                                              ('finance', 'banking'), ('retail banking', 'financial services'),
                                              ('manufacturing', 'industrial organisations')])
def test_sector_synonyms(sector, target):
    assert match_sectors(sector, [target]) == [target]
    assert match_sectors(sector, ['unrelated entertainment']) == []


def test_kev_stage_without_llm_idempotence_and_new_version(tmp_path):
    ctx = context(tmp_path)
    ctx.llm_enabled = False
    document = add_document(ctx, meta=kev())
    assert run(ctx)['by_priority']['high'] == 2
    assert not ctx.llm.prompts
    assert run(ctx)['assessments'] == 0
    ctx.db.execute('UPDATE documents SET version=2 WHERE id=?', (document,))
    assert run(ctx)['assessments'] == 2
    assert {r[0] for r in ctx.db.execute('SELECT document_version FROM relevance')} == {2}
    assert {r[0] for r in ctx.db.execute('SELECT method FROM relevance')} == {'rules'}


def test_relevance_sanitises_profile_ids_scores_missing_and_pirs(tmp_path):
    ctx = context(tmp_path)
    ctx.profiles.append(profile('negative'))
    document = add_document(ctx, kind='article')
    ctx.db.execute('''INSERT INTO analyses(document_id,document_version,status,model,created_at,analysis_json)
                     VALUES (?,1,'ok','fake',?,?)''', (document, now_iso(), dumps(analysis().model_dump())))
    def assessment(id, score):
        return dict(profile_id=id, priority='high', score=score, rationale='Relevant', matched_pirs=['P1', 'bogus', 'P1'],
                    matched_technologies=[], unknowns=['versions unknown'])
    ctx.llm = FakeBackend({'relevance': lambda _: dict(assessments=[assessment('bogus', 70), assessment('law', 999),
                                                                   assessment('law', 12), assessment('negative', -90)])})
    result = run(ctx)
    rows = {r['profile_id']: dict(r) for r in ctx.db.execute('SELECT * FROM relevance')}
    assert set(rows) == {'law', 'other', 'negative'}
    assert rows['law']['score'] == 100 and rows['negative']['score'] == 0
    assert rows['law']['method'] == 'llm' and rows['other']['method'] == 'rules'
    assert rows['other']['priority'] == 'medium'  # sector matches even without product overlap
    assert json.loads(rows['law']['matched_pirs_json']) == ['P1']
    assert result['rules_fallbacks'] == 1 and result['assessments'] == 3
    assert len(ctx.llm.prompts) == 1
    assert run(ctx)['llm_documents'] == 0


def test_rules_fallback_escalates_only_for_kev_cve_of_the_matched_product(tmp_path):
    ctx = context(tmp_path)
    ctx.profiles = [profile('exchange', vendor='Microsoft', product='Exchange Server', exposure='internal')]
    add_document(ctx, meta=kev())  # CVE-2026-1000 is Citrix NetScaler
    exchange_kev = kev()
    exchange_kev.update(cveID='CVE-2026-2000', vendorProject='Microsoft', product='Exchange Server')
    add_document(ctx, meta=exchange_kev)
    reports = {}
    for cve in ('CVE-2026-1000', 'CVE-2026-2000'):
        document = add_document(ctx, kind='article')
        report = analysis().model_copy(update={'cves': [cve], 'affected_technologies': [AffectedTechnology(
            vendor='Microsoft', product='Exchange Server', versions='', evidence_quote='Exchange Server is affected.')]})
        ctx.db.execute('''INSERT INTO analyses(document_id,document_version,status,model,created_at,analysis_json)
                         VALUES (?,1,'ok','fake',?,?)''', (document, now_iso(), dumps(report.model_dump())))
        reports[cve] = document
    ctx.llm = FakeBackend({'relevance': lambda _: dict(assessments=[])})
    assert run(ctx)['rules_fallbacks'] == 2
    priority = {r['document_id']: r['priority'] for r in ctx.db.execute("SELECT * FROM relevance WHERE profile_id='exchange'")}
    assert priority[reports['CVE-2026-1000']] == 'medium'
    assert priority[reports['CVE-2026-2000']] == 'high'


def test_disabled_analyses_and_relevance_errors_retry(tmp_path):
    ctx = context(tmp_path)
    document = add_document(ctx, kind='article')
    ctx.db.execute('''INSERT INTO analyses(document_id,document_version,status,model,created_at,analysis_json)
                     VALUES (?,1,'ok','fake',?,?)''', (document, now_iso(), dumps(analysis().model_dump())))
    ctx.llm_enabled = False
    assert run(ctx)['assessments'] == 0
    assert not ctx.llm.prompts
    ctx.llm_enabled = True
    def fail(_):
        raise LLMError('offline')
    ctx.llm = FakeBackend({'relevance': fail})
    failed = run(ctx)
    assert failed['errors'] == 1 and failed['status'] == 'error'
    assert ctx.db.execute('SELECT COUNT(*) FROM relevance').fetchone()[0] == 0
    add_document(ctx, meta=kev())
    mixed = run(ctx)
    assert mixed['status'] == 'partial'
    assert mixed['errors'] == 1 and mixed['assessments'] == 2
    ctx.llm_limit = 0
    assert run(ctx)['deferred'] == 1
