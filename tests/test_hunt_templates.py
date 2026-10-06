import json
import re
from pathlib import Path

import pytest

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


def test_all_profile_yamls_load_with_complete_table_coverage():
    assert {p.id for p in PROFILES} == {'law-firm', 'retail-bank', 'manufacturer-ot'}
    for p in PROFILES:
        assert set(p.telemetry) <= SCHEMAS.keys()
        assert len(p.telemetry) == len(set(p.telemetry))
        assert p.region == 'United Kingdom'
    assert all('TimeGenerated' in cols for cols in SCHEMAS.values())
    assert all('Timestamp' in SCHEMAS[t] for t in ('DeviceProcessEvents', 'EmailEvents', 'CloudAppEvents'))
    law = next(p for p in PROFILES if p.id == 'law-firm')
    bank = next(p for p in PROFILES if p.id == 'retail-bank')
    manufacturer = next(p for p in PROFILES if p.id == 'manufacturer-ot')
    assert (law.retention_days, bank.retention_days, manufacturer.retention_days) == (90, 365, 30)
    assert (len(law.pirs), len(bank.pirs), len(manufacturer.pirs)) == (4, 5, 4)
    assert all(pir.keywords for p in PROFILES for pir in p.pirs)
    assert {'SecurityEvent', 'Syslog', 'DnsEvents', 'AzureActivity'} <= set(bank.telemetry)
    assert not any(t.startswith('Email') for t in manufacturer.telemetry)
    assert 'OfficeActivity' not in manufacturer.telemetry
    assert any(t.exposure == 'ot' and t.vendor == 'Siemens' for t in manufacturer.technologies)
    assert any(t.exposure == 'ot' and t.vendor == 'Rockwell Automation' for t in manufacturer.technologies)


@pytest.mark.parametrize('profile', PROFILES, ids=lambda p: p.id)
def test_all_sweep_families_only_use_available_valid_schema(profile):
    inputs = [indicator('ipv4', '203.0.113.5'), indicator('ipv6', '2001:db8::5'),
              indicator('domain', 'evil.example'), indicator('url', 'https://evil.example/get'),
              indicator('md5', 'b' * 32), indicator('sha1', 'c' * 40), indicator('sha256', 'a' * 64)]
    sweeps = build_sweeps(profile, inputs)
    assert {s.family for s in sweeps} == {'ip', 'domain', 'url', 'hash'}
    for sweep in sweeps:
        checked = validate_kql(sweep.query.kql, SCHEMAS, profile.telemetry)
        assert checked.status == 'schema_valid', checked.model_dump()
        assert set(checked.tables) == set(sweep.query.tables)
        assert set(sweep.query.tables) <= set(profile.telemetry)
        assert sweep.generated_by == 'template'
        assert sweep.kind == 'ioc_sweep'
        assert sweep.query.kql.startswith('let lookback = 30d;')
        assert 'TimeGenerated >= ago(lookback)' in sweep.query.kql
        assert 'MatchedIndicator' in sweep.query.kql
        assert 'SourceTable' in sweep.query.kql
        assert 1 <= len(sweep.query.benign_explanations) <= 2
        assert len(sweep.query.pivots) == 2
        if len(sweep.query.tables) > 1:
            assert 'union isfuzzy=true' in sweep.query.kql


def test_ip_deduplication_cap_and_warninglist_exclusion():
    inputs = [indicator('ipv4', f'203.0.{i // 256}.{i % 256}') for i in range(205)]
    inputs += [inputs[0], indicator('ipv4', '10.0.0.1', 'RFC1918')]
    sweeps = build_sweeps(PROFILES[0], inputs)
    assert len(sweeps) == 1
    got = values(sweeps[0])
    assert len(got) == len(set(got)) == 200
    assert '10.0.0.1' not in got
    assert '205' in sweeps[0].query.purpose


def test_sweep_triage_guidance_differs_by_family():
    inputs = [indicator('ipv4', '203.0.113.5'), indicator('domain', 'evil.example'),
              indicator('url', 'https://evil.example/get'), indicator('sha256', 'a' * 64)]
    sweeps = build_sweeps(PROFILES[0], inputs)
    assert len(sweeps) == 4
    assert len({tuple(s.query.pivots) for s in sweeps}) == 4
    assert len({tuple(s.query.benign_explanations) for s in sweeps}) == 4


def test_hash_case_normalisation_and_deduplication():
    sweep = build_sweeps(PROFILES[0], [indicator('sha256', 'A' * 64), indicator('sha256', 'a' * 64)])[0]
    assert sweep.family == 'hash'
    assert values(sweep) == ['a' * 64]
    assert 'SHA256 in~ (iocs)' in sweep.query.kql


def test_absent_indicator_families_never_generate_empty_queries():
    assert build_sweeps(PROFILES[0], []) == []
    assert build_sweeps(PROFILES[0], [indicator('cve', 'CVE-2026-12345')]) == []
    only_ip = build_sweeps(PROFILES[0], [indicator('ipv4', '203.0.113.9')])
    assert [s.family for s in only_ip] == ['ip']


def test_warninglisted_only_generates_no_sweep():
    assert build_sweeps(PROFILES[0], [indicator('domain', 'microsoft.com', 'Top domains')]) == []


def test_no_supported_table_generates_no_sweep():
    limited = PROFILES[0].model_copy(update={'telemetry': ['DeviceInfo']})
    assert build_sweeps(limited, [indicator('ipv4', '203.0.113.2'), indicator('domain', 'evil.example')]) == []


def test_short_retention_and_single_table_do_not_require_union():
    limited = PROFILES[0].model_copy(update={'telemetry': ['DeviceNetworkEvents'], 'retention_days': 5})
    sweep = build_sweeps(limited, [indicator('ipv4', '203.0.113.8')])[0]
    assert sweep.query.kql.startswith('let lookback = 5d;')
    assert 'union' not in sweep.query.kql
    assert sweep.query.tables == ['DeviceNetworkEvents']


def test_domain_sweep_checks_subdomains_and_returns_matched_ioc():
    sweep = build_sweeps(PROFILES[0], [indicator('domain', 'Evil.Example')])[0]
    assert values(sweep) == ['evil.example']
    assert 'mv-apply MatchedIndicator = iocs' in sweep.query.kql
    assert 'endswith strcat(".", MatchedIndicator)' in sweep.query.kql


def test_domain_prefilter_uses_alphanumeric_terms_not_dotted_iocs():
    # Microsoft Learn: has_any is a whole-term operator. Dotted names are
    # multiple terms, so using a dotted IOC as the prefilter can miss matches.
    sweep = build_sweeps(PROFILES[0], [indicator('domain', 'longmalwarehost.test')])[0]
    assert 'let ioc_terms = dynamic(["longmalwarehost"]);' in sweep.query.kql
    assert 'RemoteUrl has_any (ioc_terms)' in sweep.query.kql
    assert 'has_any (iocs)' not in sweep.query.kql
    assert 'MatchedIndicator = iocs' in sweep.query.kql
