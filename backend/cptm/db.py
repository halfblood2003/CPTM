"""SQLite persistence layer (aiosqlite)."""
import os
import sqlite3

import aiosqlite

DB_PATH = os.environ.get("CPTM_DB", "/data/cptm.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT DEFAULT 'general',
    docker_image TEXT NOT NULL,
    command_template TEXT NOT NULL,
    params_json TEXT NOT NULL DEFAULT '[]',
    output_type TEXT NOT NULL DEFAULT 'raw',
    entrypoint_json TEXT DEFAULT 'null',
    built_in INTEGER NOT NULL DEFAULT 0,
    -- set when the user edits a built-in, so seeding stops refreshing it
    modified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    container_id TEXT DEFAULT '',
    exit_code INTEGER,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    output_text TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '{}',
    error TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_artifacts_job ON artifacts(job_id);
"""


async def connect() -> aiosqlite.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = await aiosqlite.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA foreign_keys=ON")
    return conn


async def init_db() -> None:
    conn = await connect()
    try:
        await conn.executescript(SCHEMA)
        await conn.commit()
        await _migrate(conn)
    finally:
        await conn.close()


async def _migrate(conn: aiosqlite.Connection) -> None:
    """Additive migrations for databases created by earlier versions."""
    cur = await conn.execute("PRAGMA table_info(tools)")
    cols = {row[1] for row in await cur.fetchall()}
    if "modified" not in cols:
        await conn.execute(
            "ALTER TABLE tools ADD COLUMN modified INTEGER NOT NULL DEFAULT 0"
        )
        await conn.commit()
