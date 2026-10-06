from pathlib import Path

import pytest

from tipipeline.config import load_table_schemas
from tipipeline.hunt.kql import rewrite_lookback, strip_comments_and_strings, validate_kql

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = load_table_schemas(ROOT)


def test_valid_query_has_no_validation_messages():
    result = validate_kql(
        'let lookback = 14d; DeviceProcessEvents | where TimeGenerated >= ago(lookback) '
        '| where FileName in~ ("powershell.exe", "pwsh.exe") '
        '| project TimeGenerated, DeviceName, ProcessCommandLine', SCHEMAS, ['DeviceProcessEvents'],
    )
    assert result.status == 'schema_valid'
    assert result.tables == ['DeviceProcessEvents']
    assert result.unknown_columns == []
    assert result.messages == []


@pytest.mark.parametrize('query', [
    'ImaginaryTable | where TimeGenerated > ago(1d)',
    'let days = 1d; ImaginaryTable | take 10',
    'union DeviceInfo, ImaginaryTable | take 10',
    'DeviceInfo | join kind=inner (ImaginaryTable | project DeviceName) on DeviceName',
    '(ImaginaryTable | take 10)',
    'let source = ImaginaryTable | take 1; source | take 1',
])
def test_unknown_table_at_tabular_expression_starts(query):
    result = validate_kql(query, SCHEMAS, SCHEMAS)
    assert result.status == 'invalid'
    assert result.unknown_tables == ['ImaginaryTable']


def test_unavailable_table_is_invalid_not_excluded():
    result = validate_kql('EmailEvents | project TimeGenerated, Subject', SCHEMAS, ['DeviceProcessEvents'])
    assert result.status == 'invalid'
    assert result.unavailable_tables == ['EmailEvents']
    assert result.tables == ['EmailEvents']


def test_column_typo_is_warning():
    result = validate_kql('DeviceProcessEvents | project TimeGenerated, DeviceNmae', SCHEMAS, ['DeviceProcessEvents'])
    assert result.status == 'warnings'
    assert result.unknown_columns == ['DeviceNmae']


def test_let_extend_project_summarize_and_rename_aliases_are_not_columns():
    result = validate_kql('''
    let lookback = 14d;
    let image = "powershell.exe";
    let subset = DeviceProcessEvents | where TimeGenerated >= ago(lookback);
    subset
    | where FileName =~ image
    | extend Cmd = tolower(ProcessCommandLine), Host = DeviceName
    | summarize Count = count(), First = min(TimeGenerated) by Host, Cmd
    | project Host, Count, First, Cmd
    | project-rename ComputerName = Host
    ''', SCHEMAS, ['DeviceProcessEvents'])
    assert result.status == 'schema_valid'
    assert result.tables == ['DeviceProcessEvents']
    assert result.unknown_columns == []


def test_comments_and_strings_are_not_references():
    result = validate_kql('''// BogusTable | project ImaginaryColumn
    DeviceProcessEvents
    /* EmailEvents | extend Typo = Nonesuch */
    | where ProcessCommandLine contains "https://GhostTable/ColName"
    | where ProcessCommandLine !contains @"OtherTable\\Foo"
    | where FileName != 'QuotedGhost'
    | project TimeGenerated, DeviceName
    ''', SCHEMAS, ['DeviceProcessEvents'])
    assert result.status == 'schema_valid'
    assert result.tables == ['DeviceProcessEvents']
    assert result.unknown_columns == []


def test_union_parameters_and_dynamic_properties():
    result = validate_kql('''let lookback = 7d;
    union isfuzzy=true withsource=SourceTable
      (SigninLogs | where TimeGenerated > ago(lookback)
       | extend OS = tostring(DeviceDetail.operatingSystem)
       | project TimeGenerated, User = UserPrincipalName, OS),
      (DeviceProcessEvents | where TimeGenerated > ago(lookback)
       | project TimeGenerated, User = AccountUpn, OS = "Windows")
    | project TimeGenerated, SourceTable, User, OS
    ''', SCHEMAS, ['SigninLogs', 'DeviceProcessEvents'])
    assert result.status == 'schema_valid'
    assert result.unknown_columns == []


def test_lookback_changes_binding_not_comment_or_string():
    original = '// let lookback = 99d;\nlet label = "let lookback = 88d;";\nlet lookback = 14d;\nDeviceInfo | where TimeGenerated >= ago(lookback)'
    rewritten = rewrite_lookback(original, 7)
    assert '// let lookback = 99d;' in rewritten
    assert '"let lookback = 88d;"' in rewritten
    assert '\nlet lookback = 7d;' in rewritten
    assert 'let lookback = 14d;' not in rewritten


@pytest.mark.parametrize(('retention', 'expected'), [(365, 365), (90, 90), (30, 30), (5, 5)])
def test_behaviour_lookback_uses_profile_retention(retention, expected):
    query = rewrite_lookback('let lookback = 14d; DeviceInfo | take 1', retention)
    assert query.startswith(f'let lookback = {expected}d;')


def test_no_table_cannot_be_a_confirmed_hunt():
    assert validate_kql('print value = 1', SCHEMAS, []).status == 'invalid'


def test_literal_escapes_and_multiline_literals_are_blanked():
    text = 'DeviceInfo | extend a = @"one""two", b = "esc\\\"aped", c = ```foo /* bar */\nGhostTable```'
    cleaned = strip_comments_and_strings(text)
    assert 'GhostTable' not in cleaned
    assert 'DeviceInfo' in cleaned
    assert cleaned.count('\n') == text.count('\n')


def test_parenthesised_scalar_predicates_are_not_tables():
    checked = validate_kql(
        'DeviceProcessEvents | where ((FileName == "powershell.exe")) or (ProcessCommandLine contains "encoded")',
        SCHEMAS, ['DeviceProcessEvents'],
    )
    assert checked.status == 'schema_valid'
    assert checked.unknown_tables == []
