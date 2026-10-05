from datetime import UTC, datetime, timedelta

import pytest

from tipipeline import process
from tipipeline.collect import Document, _store
from tipipeline.db import connect, init_db
from tipipeline.llm import FakeBackend
from tipipeline.models import Settings
from tipipeline.pipeline import Context


@pytest.fixture
def ctx(tmp_path):
    db = connect(tmp_path / 'process.db')
    init_db(db)
    context = Context(root=tmp_path, settings=Settings(), sources=[], profiles=[], db=db, llm=FakeBackend())
    yield context
    db.close()


def insert(ctx, title, text, age=1, kind='article'):
    url = 'https://report.test/' + str(ctx.db.execute('SELECT COUNT(*) FROM documents').fetchone()[0] + 1)
    doc = Document('research', 'research', kind, url, url, title, text,
                   (datetime.now(UTC) - timedelta(days=age)).isoformat(timespec='seconds'))
    return _store(ctx, doc)[0]


BODY = '''The adversary delivered a spreadsheet containing an embedded macro through targeted email.
Upon execution the victim endpoint launched a PowerShell downloader from a temporary directory.
The payload established persistence by installing a scheduled task named NetworkHealthCheck.
Operators used stolen credentials to connect to additional hosts over remote desktop protocol.
They enumerated sensitive finance document shares and staged the files inside compressed archives.
The resulting archive was uploaded to external infrastructure controlled by the intrusion operator.
Investigators identified the initial malicious attachment and tracked the subsequent endpoint activity.
The intrusion timeline shows several hours between initial execution and the first lateral connection.
Detection opportunities include unusual scheduled task creation and outbound access to rare domains.'''


def test_near_duplicate_marks_newer_but_distinct_report_stays_original(ctx):
    original = insert(ctx, 'Credential theft campaign against finance', BODY, age=3)
    newer = insert(ctx, 'Credential theft campaign against finance: update', BODY + '\nResponders reset credentials and blocked the malicious domain.', age=1)
    distinct = insert(ctx, 'Credential theft campaign against finance', 'A network device was exploited through its management API. An attacker replaced the firmware and installed a web shell. Monitoring of configuration changes revealed the malicious modification.')
    batch = insert(ctx, 'Indicators', 'Example RAT\n203.0.113.10:443', kind='ioc_batch')
    stats = process.run(ctx)
    assert stats == {'processed': 4, 'near_duplicate_links': 1, 'duplicates_marked': 1}
    docs = {row['id']: row for row in ctx.db.execute('SELECT * FROM documents')}
    assert docs[newer]['duplicate_of'] == original
    assert docs[original]['duplicate_of'] is None and docs[distinct]['duplicate_of'] is None
    assert docs[batch]['processed_version'] == 1
    link = ctx.db.execute('SELECT * FROM document_links').fetchone()
    assert (link['doc_a'], link['doc_b']) == (original, newer)
    assert link['reason'] == 'near_duplicate' and link['score'] >= .6
    assert process.run(ctx) == {'processed': 0, 'near_duplicate_links': 0, 'duplicates_marked': 0}


def test_late_older_original_repoints_duplicate_component(ctx):
    first = insert(ctx, 'Research report', BODY, age=3)
    second = insert(ctx, 'Research report republished', BODY, age=1)
    process.run(ctx)
    oldest = insert(ctx, 'Research report original', BODY, age=5)
    result = process.run(ctx)
    assert result['processed'] == 1 and result['near_duplicate_links'] == 2
    pointers = {row['id']: row['duplicate_of'] for row in ctx.db.execute('SELECT id, duplicate_of FROM documents')}
    assert pointers == {first: oldest, second: oldest, oldest: None}


def test_version_change_removes_obsolete_duplicate_relationship(ctx):
    original = insert(ctx, 'Campaign report', BODY, age=3)
    copy = insert(ctx, 'Campaign report copy', BODY)
    process.run(ctx)
    row = ctx.db.execute('SELECT * FROM documents WHERE id=?', (copy,)).fetchone()
    changed = Document(row['source_id'], row['tier'], row['kind'], row['url'], row['canonical_url'], 'Completely different malware research', 'Malicious firmware on an embedded controller interfered with the safety interlock. Serial analysis revealed a corrupted boot image and unauthorized logic changes.', row['published_at'])
    assert _store(ctx, changed)[1] == 'updated'
    stats = process.run(ctx)
    assert stats['processed'] == 1 and stats['near_duplicate_links'] == 0
    assert ctx.db.execute('SELECT COUNT(*) FROM document_links').fetchone()[0] == 0
    assert ctx.db.execute('SELECT duplicate_of FROM documents WHERE id=?', (copy,)).fetchone()[0] is None
    assert ctx.db.execute('SELECT duplicate_of FROM documents WHERE id=?', (original,)).fetchone()[0] is None
    assert ctx.db.execute('SELECT processed_version FROM documents WHERE id=?', (copy,)).fetchone()[0] == 2


def test_old_processed_candidate_outside_30_day_window_not_linked(ctx):
    old = insert(ctx, 'Old research', BODY, age=40)
    process.run(ctx)
    ctx.db.execute('UPDATE documents SET collected_at=? WHERE id=?', ((datetime.now(UTC) - timedelta(days=40)).isoformat(), old))
    new = insert(ctx, 'New research', BODY)
    result = process.run(ctx)
    assert result['near_duplicate_links'] == 0
    assert ctx.db.execute('SELECT duplicate_of FROM documents WHERE id=?', (new,)).fetchone()[0] is None


def test_short_different_texts_not_matched_on_headline_only(ctx):
    first = insert(ctx, 'Same headline', 'Malware steals credentials and exfiltrates data from finance endpoints.')
    second = insert(ctx, 'Same headline', 'Malware steals credentials and exfiltrates data from engineering endpoints.')
    assert process.run(ctx)['near_duplicate_links'] == 0
    assert [row[0] for row in ctx.db.execute('SELECT duplicate_of FROM documents')] == [None, None]


def test_two_stale_pending_documents_do_not_compare_outside_window(ctx):
    insert(ctx, 'Old report original', BODY, age=42)
    insert(ctx, 'Old report copy', BODY, age=40)
    old_collection = (datetime.now(UTC) - timedelta(days=40)).isoformat()
    ctx.db.execute('UPDATE documents SET collected_at=?', (old_collection,))
    stats = process.run(ctx)
    assert stats['processed'] == 2 and stats['near_duplicate_links'] == 0
    assert all(row[0] == 1 for row in ctx.db.execute('SELECT processed_version FROM documents'))
