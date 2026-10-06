"""SQLite storage: schema and small shared helpers.

Stage idempotency works off versions: a document's ``version`` increments
when its content changes, and each stage records which version it last
processed (``processed_version``, ``extracted_version``, or the
``document_version`` column on analyses/relevance/hunts).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','ok','partial','failed')),
  stages_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS source_fetches (
  id INTEGER PRIMARY KEY,
  run_id INTEGER REFERENCES runs(id),
  source_id TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','error','skipped')),
  items_seen INTEGER NOT NULL DEFAULT 0,
  items_new INTEGER NOT NULL DEFAULT 0,
  items_updated INTEGER NOT NULL DEFAULT 0,
  error TEXT
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY,
  source_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('article','advisory','vulnerability','ioc_batch')),
  tier TEXT NOT NULL CHECK (tier IN ('research','government','news','ioc_feed','manual')),
  url TEXT NOT NULL,
  canonical_url TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  published_at TEXT,
  collected_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  text TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}',
  duplicate_of INTEGER REFERENCES documents(id),
  cluster_id INTEGER,
  processed_version INTEGER,
  extracted_version INTEGER
);
CREATE INDEX IF NOT EXISTS idx_documents_published ON documents(published_at);
CREATE INDEX IF NOT EXISTS idx_documents_cluster ON documents(cluster_id);

CREATE TABLE IF NOT EXISTS document_versions (
  document_id INTEGER NOT NULL REFERENCES documents(id),
  version INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  title TEXT NOT NULL,
  text TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  PRIMARY KEY (document_id, version)
);

CREATE TABLE IF NOT EXISTS document_links (
  doc_a INTEGER NOT NULL REFERENCES documents(id),
  doc_b INTEGER NOT NULL REFERENCES documents(id),
  reason TEXT NOT NULL CHECK (reason IN ('near_duplicate','shared_indicator','shared_cve')),
  detail TEXT NOT NULL DEFAULT '',
  score REAL,
  PRIMARY KEY (doc_a, doc_b, reason),
  CHECK (doc_a < doc_b)
);

CREATE TABLE IF NOT EXISTS indicators (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('ipv4','ipv6','domain','url','md5','sha1','sha256','email','cve')),
  value TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE (type, value)
);

CREATE TABLE IF NOT EXISTS document_indicators (
  document_id INTEGER NOT NULL REFERENCES documents(id),
  indicator_id INTEGER NOT NULL REFERENCES indicators(id),
  context TEXT NOT NULL CHECK (context IN ('ioc_section','body','feed','metadata')),
  snippet TEXT NOT NULL DEFAULT '',
  -- Name of the matched MISP warninglist (likely benign / shared infrastructure); NULL if none.
  warninglist TEXT,
  PRIMARY KEY (document_id, indicator_id)
);

CREATE TABLE IF NOT EXISTS document_techniques (
  document_id INTEGER NOT NULL REFERENCES documents(id),
  technique_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('explicit','llm')),
  step_order INTEGER NOT NULL DEFAULT 0,
  basis TEXT CHECK (basis IN ('stated','inferred')),
  quote TEXT NOT NULL DEFAULT '',
  quote_verified INTEGER NOT NULL DEFAULT 0,
  valid INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (document_id, technique_id, source, step_order)
);

CREATE TABLE IF NOT EXISTS analyses (
  document_id INTEGER PRIMARY KEY REFERENCES documents(id),
  document_version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','error')),
  model TEXT NOT NULL,
  created_at TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  report_type TEXT,
  huntable INTEGER,
  analysis_json TEXT,
  validation_json TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS relevance (
  document_id INTEGER NOT NULL REFERENCES documents(id),
  profile_id TEXT NOT NULL,
  document_version INTEGER NOT NULL,
  priority TEXT NOT NULL CHECK (priority IN ('high','medium','low','none')),
  score INTEGER NOT NULL,
  rationale TEXT NOT NULL,
  matched_pirs_json TEXT NOT NULL DEFAULT '[]',
  matched_technologies_json TEXT NOT NULL DEFAULT '[]',
  unknowns_json TEXT NOT NULL DEFAULT '[]',
  method TEXT NOT NULL CHECK (method IN ('llm','rules')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (document_id, profile_id)
);

CREATE TABLE IF NOT EXISTS hunts (
  id INTEGER PRIMARY KEY,
  document_id INTEGER NOT NULL REFERENCES documents(id),
  profile_id TEXT NOT NULL,
  document_version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('prepared','informational')),
  title TEXT NOT NULL,
  hypothesis TEXT NOT NULL,
  package_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (document_id, profile_id)
);

CREATE TABLE IF NOT EXISTS queries (
  id INTEGER PRIMARY KEY,
  hunt_id INTEGER NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('ioc_sweep','behavioural')),
  title TEXT NOT NULL,
  purpose TEXT NOT NULL,
  kql TEXT NOT NULL,
  tables_json TEXT NOT NULL,
  technique_ids_json TEXT NOT NULL DEFAULT '[]',
  benign_json TEXT NOT NULL DEFAULT '[]',
  pivots_json TEXT NOT NULL DEFAULT '[]',
  generated_by TEXT NOT NULL CHECK (generated_by IN ('template','llm')),
  validation_status TEXT NOT NULL CHECK (validation_status IN ('schema_valid','warnings','invalid')),
  validation_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_calls (
  id INTEGER PRIMARY KEY,
  run_id INTEGER,
  task TEXT NOT NULL,
  document_id INTEGER,
  model TEXT NOT NULL,
  effort TEXT NOT NULL,
  started_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','error')),
  error TEXT
);

-- Manual investigations started from the CLI or the dashboard server.
-- kind is the resolved kind ('auto' is detected before insert).
CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('url','cve','technique','hypothesis')),
  input TEXT NOT NULL,
  profile_id TEXT,
  include_scraped INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','error')),
  result_json TEXT,
  error TEXT
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string with offset."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def upsert_indicator(conn: sqlite3.Connection, type_: str, value: str, seen_at: str) -> int:
    """Insert or touch an indicator and return its id."""
    conn.execute(
        """
        INSERT INTO indicators (type, value, first_seen, last_seen) VALUES (?, ?, ?, ?)
        ON CONFLICT (type, value) DO UPDATE SET
          last_seen = MAX(indicators.last_seen, excluded.last_seen),
          first_seen = MIN(indicators.first_seen, excluded.first_seen)
        """,
        (type_, value, seen_at, seen_at),
    )
    row = conn.execute("SELECT id FROM indicators WHERE type = ? AND value = ?", (type_, value)).fetchone()
    return int(row["id"])
