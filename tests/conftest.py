"""Shared synthetic DB fixtures; no network or real pipeline database."""
import pytest

from fixtures.sample_db import SAMPLE_NOW, build_sample_context, sample_attack, sample_profiles, sample_sources, sample_themes
from tipipeline.db import connect, init_db
from tipipeline.llm import FakeBackend
from tipipeline.models import Settings
from tipipeline.pipeline import Context


@pytest.fixture
def sample_now():
    return SAMPLE_NOW


@pytest.fixture
def sample_ctx(tmp_path):
    ctx = build_sample_context(tmp_path)
    yield ctx
    ctx.db.close()


@pytest.fixture
def empty_ctx(tmp_path):
    conn = connect(tmp_path / "empty.db")
    init_db(conn)
    ctx = Context(root=tmp_path, settings=Settings(), sources=sample_sources(), profiles=sample_profiles(), db=conn, llm=FakeBackend(), themes=sample_themes())
    ctx.__dict__["attack"] = sample_attack()
    yield ctx
    conn.close()
