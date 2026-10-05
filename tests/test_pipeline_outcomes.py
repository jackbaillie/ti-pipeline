"""Run records distinguish success, partial failure, and unavailable stages."""

import json
from types import SimpleNamespace

import pytest

from tipipeline.db import connect, init_db
from tipipeline.llm import FakeBackend
from tipipeline.models import Settings
from tipipeline.pipeline import Context, run_lock, run_pipeline


def context(tmp_path):
    db = connect(tmp_path / "state.db")
    init_db(db)
    return Context(
        root=tmp_path, settings=Settings(), sources=[], profiles=[], db=db, llm=FakeBackend()
    )


def test_partial_stage_failure_is_persisted_without_losing_successful_stages(tmp_path, monkeypatch):
    ctx = context(tmp_path)
    modules = {
        "tipipeline.collect": SimpleNamespace(run=lambda ctx: {"status": "partial", "errors": 1}),
        "tipipeline.process": SimpleNamespace(run=lambda ctx: {"documents": 3}),
    }
    monkeypatch.setattr("tipipeline.pipeline.importlib.import_module", modules.__getitem__)
    result = run_pipeline(ctx, ("collect", "process"))
    row = ctx.db.execute("SELECT * FROM runs WHERE id = ?", (result["run_id"],)).fetchone()
    assert result["status"] == "partial"
    assert row["status"] == "partial"
    assert row["finished_at"] is not None
    assert json.loads(row["stages_json"])["process"]["documents"] == 3


def test_missing_stage_is_recorded_as_failed_run(tmp_path, monkeypatch):
    ctx = context(tmp_path)

    def missing(name):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr("tipipeline.pipeline.importlib.import_module", missing)
    result = run_pipeline(ctx, ("collect",))
    row = ctx.db.execute("SELECT * FROM runs WHERE id = ?", (result["run_id"],)).fetchone()
    assert result["status"] == "failed"
    assert row["finished_at"] is not None
    assert "ModuleNotFoundError" in json.loads(row["stages_json"])["collect"]["error"]


def test_overlapping_run_is_rejected_and_lock_released(tmp_path):
    with run_lock(tmp_path):
        with pytest.raises(RuntimeError, match="another pipeline run"):
            with run_lock(tmp_path):
                pytest.fail("overlapping run was admitted")
    with run_lock(tmp_path):
        with pytest.raises(RuntimeError, match="another pipeline run"):
            with run_lock(tmp_path):
                pytest.fail("overlapping run was admitted after release")
