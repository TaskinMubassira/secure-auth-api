"""A tiny SQLite data layer. Every query uses parameters (never string formatting) to prevent SQL injection."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def create_user(self, email: str, password_hash: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()
        return cur.lastrowid

    def find_by_email(self, email: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    def find_by_id(self, user_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def record_failed_login(self, user_id: int, locked_until: str | None) -> None:
        self.conn.execute(
            "UPDATE users SET failed_logins = failed_logins + 1, locked_until = COALESCE(?, locked_until) WHERE id = ?",
            (locked_until, user_id),
        )
        self.conn.commit()

    def reset_failed_logins(self, user_id: int) -> None:
        self.conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user_id,))
        self.conn.commit()
