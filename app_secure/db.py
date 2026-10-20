"""Tiny SQLite helper used by the demo app."""
import os
import sqlite3
import tempfile

DB_PATH = os.path.join(tempfile.gettempdir(), "devsecops_demo_secure.db")

SEED_USERS = [
    ("alice", "alice@example.com", "admin"),
    ("bob", "bob@example.com", "user"),
    ("carol", "carol@example.com", "user"),
]


def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (name TEXT, email TEXT, role TEXT)")
    conn.executemany("INSERT INTO users VALUES (?, ?, ?)", SEED_USERS)
    conn.commit()
    conn.close()
