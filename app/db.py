"""SQLite storage + the tamper-evident attendance chain."""
from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager

from . import config
from .crypto_core import GENESIS_HASH, chain_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,          -- USN for students
    name          TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('student','faculty','admin')),
    pw_hash       TEXT NOT NULL,                 -- Argon2id, never the password
    device_pubkey TEXT,                          -- ECDSA P-256 SPKI (base64), bound on first scan setup
    device_fp     TEXT,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  REAL NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,                 -- SHA-256 of the cookie; a DB leak can't hijack logins
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS courses (
    id         INTEGER PRIMARY KEY,
    code       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    faculty_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS enrollments (
    course_id  INTEGER NOT NULL REFERENCES courses(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (course_id, student_id)
);
CREATE TABLE IF NOT EXISTS class_sessions (
    id         TEXT PRIMARY KEY,
    course_id  INTEGER NOT NULL REFERENCES courses(id),
    faculty_id INTEGER NOT NULL REFERENCES users(id),
    started_at REAL NOT NULL,
    closed_at  REAL,
    report_json TEXT,
    report_sig  TEXT
);
CREATE TABLE IF NOT EXISTS attendance (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES class_sessions(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    ts         REAL NOT NULL,
    method     TEXT NOT NULL CHECK (method IN ('qr','manual')),
    actor_id   INTEGER NOT NULL,                 -- who caused it (student, or faculty for overrides)
    note       TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL,
    UNIQUE (session_id, student_id)              -- one mark per student per class
);
CREATE TABLE IF NOT EXISTS used_nonces (
    nonce   TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    ts      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    session_id TEXT,
    user_id    INTEGER,
    ip         TEXT,
    kind       TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
"""

_chain_lock = threading.Lock()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as db:
        db.executescript(SCHEMA)


def log_event(db, kind: str, detail: str = "", *, session_id=None, user_id=None, ip=None) -> None:
    db.execute(
        "INSERT INTO security_events (ts, session_id, user_id, ip, kind, detail) VALUES (?,?,?,?,?,?)",
        (time.time(), session_id, user_id, ip, kind, detail),
    )


# ---------------------------------------------------------------- the chain
def record_dict(row) -> dict:
    """Exactly the fields that get hashed. Order doesn't matter (canonical JSON sorts keys)."""
    return {
        "id": row["id"],
        "session_id": row["session_id"],
        "student_id": row["student_id"],
        "ts": round(float(row["ts"]), 3),
        "method": row["method"],
        "actor_id": row["actor_id"],
        "note": row["note"],
    }


def append_attendance(db, session_id: str, student_id: int, method: str, actor_id: int, note: str = "") -> dict:
    """Append one record to the global hash chain. Raises sqlite3.IntegrityError on duplicates."""
    with _chain_lock:
        db.execute("BEGIN IMMEDIATE")
        try:
            last = db.execute("SELECT id, hash FROM attendance ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS_HASH
            next_id = (last["id"] + 1) if last else 1
            rec = {
                "id": next_id,
                "session_id": session_id,
                "student_id": student_id,
                "ts": round(time.time(), 3),
                "method": method,
                "actor_id": actor_id,
                "note": note,
            }
            h = chain_hash(prev, rec)
            db.execute(
                "INSERT INTO attendance (id, session_id, student_id, ts, method, actor_id, note, prev_hash, hash)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (rec["id"], session_id, student_id, rec["ts"], method, actor_id, note, prev, h),
            )
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
    return {**rec, "prev_hash": prev, "hash": h}


def chain_head(db) -> tuple[str, int]:
    row = db.execute("SELECT hash, id FROM attendance ORDER BY id DESC LIMIT 1").fetchone()
    return (row["hash"], row["id"]) if row else (GENESIS_HASH, 0)


def verify_chain(db) -> dict:
    """Recompute every hash. Reports the first record whose contents or links don't match."""
    expected_prev = GENESIS_HASH
    expected_id = 1
    problems = []
    rows = db.execute("SELECT * FROM attendance ORDER BY id").fetchall()
    for row in rows:
        if row["id"] != expected_id:
            problems.append({"id": row["id"], "problem": f"gap: record {expected_id} missing (deleted?)"})
        if row["prev_hash"] != expected_prev:
            problems.append({"id": row["id"], "problem": "prev_hash link broken"})
        recomputed = chain_hash(row["prev_hash"], record_dict(row))
        if recomputed != row["hash"]:
            problems.append({"id": row["id"], "problem": "contents modified (hash mismatch)"})
        expected_prev = row["hash"]  # follow the stored chain so we pinpoint the edited row
        expected_id = row["id"] + 1

    # Anchors: every signed report pinned the chain head at close time. An attacker who edits a
    # row AND recomputes every later hash still can't fix the signed heads without the signing key.
    import json

    by_id = {r["id"]: r["hash"] for r in rows}
    anchors = db.execute("SELECT id, report_json FROM class_sessions WHERE report_json IS NOT NULL").fetchall()
    for a in anchors:
        rep = json.loads(a["report_json"])
        hid, hh = rep.get("chain_head_id", 0), rep.get("chain_head")
        if hid and by_id.get(hid) != hh:
            problems.append({"id": hid, "problem": f"does not match head signed in report for session {a['id']}"})
    return {
        "ok": not problems,
        "records": len(rows),
        "head": expected_prev,
        "problems": problems,
    }
