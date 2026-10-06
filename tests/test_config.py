from pathlib import Path

import pytest
import yaml

from tipipeline.config import load_profiles, load_settings, load_themes
from tipipeline.models import ReportAnalysis

ROOT = Path(__file__).resolve().parents[1]


def test_repository_profiles_attach_a_known_theme_to_every_pir():
    themes = load_themes(ROOT)
    profiles = load_profiles(ROOT, themes)
    theme_ids = {t.id for t in themes}
    assert len(profiles) == 3
    assert all(pir.theme in theme_ids for p in profiles for pir in p.pirs)
    # Entra / Microsoft 365 token theft applies to every customer.
    assert all(any(pir.theme == 'identity' for pir in p.pirs) for p in profiles)
    assert all(len({pir.id for pir in p.pirs}) == len(p.pirs) for p in profiles)


def test_unknown_pir_theme_is_rejected_at_load(tmp_path):
    (tmp_path / 'config' / 'profiles').mkdir(parents=True)
    (tmp_path / 'config' / 'priorities.yaml').write_text(yaml.safe_dump(
        {'themes': [{'id': 'edge', 'name': 'Edge', 'description': 'Edge devices.'}]}))
    profile = dict(id='x', name='X', sector='Legal services', region='United Kingdom', description='Test.',
                   crown_jewels=[], technologies=[],
                   pirs=[{'id': 'X-PIR-1', 'question': 'Edge?', 'theme': 'edge'},
                         {'id': 'X-PIR-2', 'question': 'Other?', 'theme': 'not-a-theme'}])
    (tmp_path / 'config' / 'profiles' / 'x.yaml').write_text(yaml.safe_dump(profile))
    with pytest.raises(ValueError, match='X-PIR-2'):
        load_profiles(tmp_path)
    profile['pirs'].pop()
    (tmp_path / 'config' / 'profiles' / 'x.yaml').write_text(yaml.safe_dump(profile))
    assert [pir.theme for pir in load_profiles(tmp_path)[0].pirs] == ['edge']


def test_hunt_settings_load():
    settings = load_settings(ROOT)
    assert settings.hunt.lookback_days > 0
    assert isinstance(settings.hunt.include_scraped_iocs, bool)


def test_roundup_report_type_accepted():
    report = ReportAnalysis(summary='Weekly digest.', report_type='roundup', huntable=False, huntable_reason='Digest.',
                            threat_actors=[], malware=[], tools=[], affected_technologies=[], cves=[],
                            targeted_sectors=[], targeted_regions=[], attack_steps=[])
    assert report.report_type == 'roundup'
