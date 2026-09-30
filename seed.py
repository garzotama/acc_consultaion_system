
from werkzeug.security import generate_password_hash
from config import Config
import sqlite3

DEFAULT_USERS = [
    ("admin", "Admin@123", "ACC Super Administrator", "admin@acc.local", "super_admin"),
    ("medical", "Medical@123", "ACC Medical Staff", "medical@acc.local", "medical"),
    ("student", "Student@123", "ACC Student", "student@acc.local", "student"),
]


def seed():
    connection = sqlite3.connect(Config.DATABASE)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        # Create the same schema used by the Flask application.
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
        connection.executescript(schema)

        for username, password, full_name, email, role in DEFAULT_USERS:
            existing = connection.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                continue

            connection.execute(
                """
                INSERT INTO users
                    (username, password_hash, full_name, email, role, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (username, generate_password_hash(password), full_name, email, role),
            )

        connection.commit()
        print("Database seeded successfully.")
        print("Super Admin -> admin / Admin@123")
        print("Medical     -> medical / Medical@123")
        print("Student     -> student / Student@123")
    finally:
        connection.close()


if __name__ == "__main__":
    seed()
