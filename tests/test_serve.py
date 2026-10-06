"""Live pages and one-worker queue against a temporary database; no remote requests or model calls."""
import http.client
import threading
from urllib.parse import urlencode

import pytest

from tipipeline.dashboard.investigations import live_investigation, render_pages
from tipipeline.dashboard import page_shell
from tipipeline.db import now_iso
from tipipeline.investigate import create_investigation, get_investigation, run_investigation
from tipipeline.serve import DashboardServer


@pytest.fixture
def server(sample_ctx):
    sample_ctx.settings = sample_ctx.settings.model_copy(update={"db_path": "sample.db"})
    folder = sample_ctx.output_dir / "dashboard"
    folder.mkdir(parents=True)
    (folder / "index.html").write_text("Dashboard index")
    instance = DashboardServer(("127.0.0.1", 0), sample_ctx, hostnames=("host.example.ts.net", "host"))
    instance.start_worker()
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.worker.stop(5)
    instance.server_close()
    thread.join(5)


def request(server, method, path, data=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    body = urlencode(data) if data is not None else None
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read().decode()
    connection.close()
    return result


def test_post_creates_redirects_and_get_is_live(server):
    status, headers, _ = request(server, "POST", "/dashboard/investigate", {"value": "CVE-2020-0001", "kind": "auto"})
    assert status == 303 and headers["Location"] == "/dashboard/investigations/1.html"
    # stop() drains the queue, making completion deterministic without polling.
    server.worker.stop(5)
    status, headers, page = request(server, "GET", headers["Location"])
    assert status == 200 and headers["Cache-Control"] == "no-store"
    assert "CVE-2020-0001" in page and "No collected reports mention CVE-2020-0001" in page
    assert 'chip-ok">done' in page and 'http-equiv="refresh"' not in page
    # The DB is read live, without a pipeline dashboard render or a file being written.
    assert not (server.output_root / "dashboard" / "investigations" / "1.html").exists()
    with server.thread_context().db as conn:
        conn.execute("UPDATE investigations SET error='Live DB change' WHERE id=1")
    assert "Live DB change" in request(server, "GET", "/dashboard/investigations/1.html")[2]


def test_get_root_and_static_files(server):
    assert request(server, "GET", "/")[1]["Location"] == "/dashboard/"
    assert request(server, "GET", "/dashboard/") == (200, request(server, "GET", "/dashboard/")[1], "Dashboard index")
    status, _, page = request(server, "GET", "/dashboard/investigate.html")
    assert status == 200 and 'method="post" action="investigate"' in page and "General investigation" in page
    assert "Investigations run through the dashboard server" not in page
    assert request(server, "GET", "/dashboard/investigations/999.html")[0] == 404


@pytest.mark.parametrize("path", ["/../sample.db", "/%2e%2e/sample.db", "/dashboard/%2e%2e/%2e%2e/sample.db", "/%00"])
def test_traversal_refused(server, path):
    assert request(server, "GET", path)[0] == 404


def test_post_validation_and_cross_site_refusal(server):
    assert request(server, "POST", "/dashboard/investigate", {"value": "x" * 2001})[0] == 400
    assert request(server, "POST", "/dashboard/investigate", {"value": "T1133", "customer": "nobody"})[0] == 400
    assert request(server, "POST", "/dashboard/investigate", {"value": "T1133"}, {"Origin": "https://elsewhere.example"})[0] == 403
    assert request(server, "POST", "/dashboard/investigate", {"value": "x" * 33000})[0] == 413
    assert request(server, "POST", "/other", {"value": "T1133"})[0] == 404


def test_only_one_worker_runs_and_pending_pages_refresh(sample_ctx):
    sample_ctx.settings = sample_ctx.settings.model_copy(update={"db_path": "sample.db"})
    first_started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls = []
    ids = []
    def runner(ctx, investigation_id):
        calls.append(threading.get_ident())
        ids.append(investigation_id)
        if len(ids) == 1:
            ctx.db.execute("UPDATE investigations SET status='running' WHERE id=?", (investigation_id,))
            ctx.db.commit()
            first_started.set()
            assert release.wait(5)
        run_investigation(ctx, investigation_id)
        if len(ids) == 2:
            finished.set()
    server = DashboardServer(("127.0.0.1", 0), sample_ctx, runner=runner)
    server.start_worker()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request(server, "POST", "/dashboard/investigate", {"value": "CVE-2020-0001"})
        assert first_started.wait(5)
        request(server, "POST", "/dashboard/investigate", {"value": "CVE-2020-0002"})
        assert ids == [1]
        for investigation_id, state in [(1, "running"), (2, "queued")]:
            status, _, page = request(server, "GET", f"/dashboard/investigations/{investigation_id}.html")
            assert status == 200 and state in page and 'http-equiv="refresh" content="5"' in page
        release.set()
        assert finished.wait(5) and ids == [1, 2] and len(set(calls)) == 1
    finally:
        release.set()
        server.shutdown()
        server.worker.stop(5)
        server.server_close()
        thread.join(5)


def test_static_and_live_pages_use_same_templates(sample_ctx):
    investigation_id = create_investigation(sample_ctx, "CVE-2020-0001")
    run_investigation(sample_ctx, investigation_id)
    env, common = page_shell(sample_ctx)
    pages = render_pages(sample_ctx, env, common)
    assert "investigate.html" in pages and "investigations/1.html" in pages
    assert "Investigations run through the dashboard server" in pages["investigate.html"]
    assert "No collected reports mention CVE-2020-0001" in pages["investigations/1.html"]
    assert "No collected reports mention CVE-2020-0001" in live_investigation(sample_ctx, investigation_id)

def test_static_symlinks_cannot_escape_output(server):
    outside = server.context.root / "outside.txt"
    outside.write_text("must not be served")
    (server.output_root / "linked.txt").symlink_to(outside)
    nested = server.output_root / "nested"
    nested.mkdir()
    (nested / "index.html").symlink_to(outside)
    assert request(server, "GET", "/linked.txt")[0] == 404
    assert request(server, "GET", "/nested/")[0] == 404


def test_untrusted_matching_host_and_origin_are_refused_before_queueing(server):
    headers = {"Host": f"attacker.example:{server.server_port}", "Origin": f"http://attacker.example:{server.server_port}"}
    assert request(server, "GET", "/dashboard/investigate.html", headers=headers)[0] == 403
    assert request(server, "POST", "/dashboard/investigate", {"value": "T1133"}, headers)[0] == 403
    conn = server.thread_context().db
    try:
        assert conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == 0
    finally:
        conn.close()


def test_explicit_magicdns_alias_is_accepted_with_matching_origin(server):
    alias = f"host.example.ts.net:{server.server_port}"
    headers = {"Host": alias, "Origin": f"http://{alias}"}
    assert request(server, "GET", "/dashboard/investigate.html", headers=headers)[0] == 200
    assert request(server, "POST", "/dashboard/investigate", {"value": "CVE-2020-0001"}, headers)[0] == 303
    wrong_port = {**headers, "Origin": "http://host.example.ts.net:1"}
    assert request(server, "POST", "/dashboard/investigate", {"value": "T1133"}, wrong_port)[0] == 403


def test_url_investigation_waits_for_pipeline_lock_and_shows_waiting(server, monkeypatch):
    from contextlib import contextmanager
    from tipipeline import investigate
    from tipipeline.pipeline import run_lock
    waiting = threading.Event()
    fetched = threading.Event()
    @contextmanager
    def observed_lock(data_dir, *, blocking=False):
        assert blocking
        waiting.set()
        with run_lock(data_dir, blocking=blocking):
            yield
    def lookup(ctx, url):
        fetched.set()
        return investigate._Found(focus="Submitted report", empty="No collected evidence.")
    monkeypatch.setattr(investigate, "run_lock", observed_lock)
    monkeypatch.setattr(investigate, "_url_lookup", lookup)
    with run_lock(server.context.data_dir):
        assert request(server, "POST", "/dashboard/investigate", {"value": "https://public.example/report"})[0] == 303
        assert waiting.wait(5)
        assert not fetched.is_set()
        page = request(server, "GET", "/dashboard/investigations/1.html")[2]
        assert "Waiting for the pipeline lock" in page and 'http-equiv="refresh" content="5"' in page
    assert fetched.wait(5)
    server.worker.stop(5)
    assert "No collected evidence." in request(server, "GET", "/dashboard/investigations/1.html")[2]
