import json
import re
from pathlib import Path

from tipipeline.config import load_profiles, load_table_schemas
from tipipeline.hunt.kql import validate_kql
from tipipeline.hunt.templates import build_sweeps

ROOT = Path(__file__).resolve().parents[1]
PROFILES = load_profiles(ROOT)
SCHEMAS = load_table_schemas(ROOT)


def indicator(type_, value, warninglist=None):
    return {'type': type_, 'value': value, 'warninglist': warninglist}


def values(sweep):
    return json.loads(re.search(r'let iocs = dynamic\((.*?)\);', sweep.query.kql).group(1))


def test_profiles_load_and_catalogue_has_standard_columns():
    assert {p.id for p in PROFILES} == {'law-firm', 'retail-bank', 'manufacturer-ot'}
    assert all(p.region == 'United Kingdom' for p in PROFILES)
    assert all(pir.keywords for p in PROFILES for pir in p.pirs)
    assert all('TimeGenerated' in cols for cols in SCHEMAS.values())
    assert all('Timestamp' in SCHEMAS[t] for t in ('DeviceProcessEvents', 'EmailEvents', 'CloudAppEvents'))
    manufacturer = next(p for p in PROFILES if p.id == 'manufacturer-ot')
    assert any(t.exposure == 'ot' and t.vendor == 'Siemens' for t in manufacturer.technologies)
    assert any(t.exposure == 'ot' and t.vendor == 'Rockwell Automation' for t in manufacturer.technologies)


def test_every_sweep_family_unions_all_relevant_catalogue_tables():
    inputs = [indicator('ipv4', '203.0.113.5'), indicator('ipv6', '2001:db8::5'),
              indicator('domain', 'evil.example'), indicator('url', 'https://evil.example/get'),
              indicator('md5', 'b' * 32), indicator('sha1', 'c' * 40), indicator('sha256', 'a' * 64)]
    sweeps = build_sweeps(inputs, 30)
    assert {s.family for s in sweeps} == {'ip', 'domain', 'url', 'hash'}
    tables = {s.family: set(s.query.tables) for s in sweeps}
    # Appliance, identity, endpoint and email logs are swept regardless of customer.
    assert {'CommonSecurityLog', 'SigninLogs', 'DeviceNetworkEvents', 'EmailEvents', 'SecurityEvent'} <= tables['ip']
    assert {'DnsEvents', 'CommonSecurityLog', 'UrlClickEvents'} <= tables['domain']
    assert {'DeviceFileEvents', 'DeviceProcessEvents', 'EmailAttachmentInfo'} <= tables['hash']
    for sweep in sweeps:
        checked = validate_kql(sweep.query.kql, SCHEMAS)
        assert checked.status == 'schema_valid', checked.model_dump()
        assert set(checked.tables) == set(sweep.query.tables)
        assert sweep.generated_by == 'template'
        assert sweep.kind == 'ioc_sweep'
        assert sweep.query.kql.startswith('let lookback = 30d;')
        assert sweep.query.kql.count('TimeGenerated >= ago(lookback)') == len(sweep.query.tables)
        assert 'union isfuzzy=true' in sweep.query.kql
        assert 'MatchedIndicator' in sweep.query.kql
        assert 'SourceTable' in sweep.query.kql
        assert 1 <= len(sweep.query.benign_explanations) <= 2
        assert len(sweep.query.pivots) == 2


def test_ip_deduplication_cap_and_warninglist_exclusion():
    inputs = [indicator('ipv4', f'203.0.{i // 256}.{i % 256}') for i in range(205)]
    inputs += [inputs[0], indicator('ipv4', '10.0.0.1', 'RFC1918')]
    sweeps = build_sweeps(inputs, 30)
    assert len(sweeps) == 1
    got = values(sweeps[0])
    assert len(got) == len(set(got)) == 200
    assert '10.0.0.1' not in got
    assert '205' in sweeps[0].query.purpose


def test_sweep_triage_guidance_differs_by_family():
    inputs = [indicator('ipv4', '203.0.113.5'), indicator('domain', 'evil.example'),
              indicator('url', 'https://evil.example/get'), indicator('sha256', 'a' * 64)]
    sweeps = build_sweeps(inputs, 30)
    assert len(sweeps) == 4
    assert len({tuple(s.query.pivots) for s in sweeps}) == 4
    assert len({tuple(s.query.benign_explanations) for s in sweeps}) == 4


def test_hash_case_normalisation_and_deduplication():
    sweep = build_sweeps([indicator('sha256', 'A' * 64), indicator('sha256', 'a' * 64)], 30)[0]
    assert sweep.family == 'hash'
    assert values(sweep) == ['a' * 64]
    assert 'SHA256 in~ (iocs)' in sweep.query.kql


def test_absent_indicator_families_never_generate_empty_queries():
    assert build_sweeps([], 30) == []
    assert build_sweeps([indicator('cve', 'CVE-2026-12345')], 30) == []
    only_ip = build_sweeps([indicator('ipv4', '203.0.113.9')], 30)
    assert [s.family for s in only_ip] == ['ip']


def test_warninglisted_only_generates_no_sweep():
    assert build_sweeps([indicator('domain', 'microsoft.com', 'Top domains')], 30) == []


def test_configured_lookback_sets_the_sweep_window():
    sweep = build_sweeps([indicator('ipv4', '203.0.113.8')], 5)[0]
    assert sweep.query.kql.startswith('let lookback = 5d;')


def test_domain_sweep_checks_subdomains_and_returns_matched_ioc():
    sweep = build_sweeps([indicator('domain', 'Evil.Example')], 30)[0]
    assert values(sweep) == ['evil.example']
    assert 'mv-apply MatchedIndicator = iocs' in sweep.query.kql
    assert 'endswith strcat(".", MatchedIndicator)' in sweep.query.kql


def test_domain_prefilter_uses_alphanumeric_terms_not_dotted_iocs():
    # Microsoft Learn: has_any is a whole-term operator. Dotted names are
    # multiple terms, so using a dotted IOC as the prefilter can miss matches.
    sweep = build_sweeps([indicator('domain', 'longmalwarehost.test')], 30)[0]
    assert 'let ioc_terms = dynamic(["longmalwarehost"]);' in sweep.query.kql
    assert 'RemoteUrl has_any (ioc_terms)' in sweep.query.kql
    assert 'has_any (iocs)' not in sweep.query.kql
    assert 'MatchedIndicator = iocs' in sweep.query.kql
