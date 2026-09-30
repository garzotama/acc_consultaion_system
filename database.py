
import sqlite3
from contextlib import contextmanager
from flask import current_app


def get_connection():
    """Create a SQLite connection configured for dictionary-like rows."""
    connection = sqlite3.connect(current_app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def get_db():
    """Open a database connection and automatically commit/close it."""
    connection = get_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    """Create all tables and indexes required by the application."""
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL CHECK(role IN ('super_admin', 'medical', 'student')),
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS consultations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        medical_id INTEGER,
        concern TEXT NOT NULL,
        preferred_date TEXT,
        preferred_time TEXT,
        status TEXT NOT NULL DEFAULT 'Pending'
            CHECK(status IN ('Pending', 'Accepted', 'In Progress', 'Completed', 'Cancelled')),
        medical_notes TEXT,
        student_notes TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE RESTRICT,
        FOREIGN KEY(medical_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_consultations_student ON consultations(student_id);
    CREATE INDEX IF NOT EXISTS idx_consultations_medical ON consultations(medical_id);
    CREATE INDEX IF NOT EXISTS idx_consultations_status ON consultations(status);
    CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at);
    """
    with get_db() as db:
        db.executescript(schema)


def log_activity(user_id, action, details=""):
    """Record an important user/system action for the admin activity report."""
    with get_db() as db:
        db.execute(
            "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
            (user_id, action, details),
        )
