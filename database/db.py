import sqlite3
from pathlib import Path
from config.settings import settings


def get_db_connection(db_path: Path = None) -> sqlite3.Connection:
    """Create and return SQLite database connection with foreign keys enabled."""
    target_path = db_path or settings.DB_PATH
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(target_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce foreign key constraints strictly
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path = None) -> None:
    """Initialize database tables with schema migrations."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            session_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            total_records INTEGER NOT NULL,
            parsed_records INTEGER NOT NULL,
            malformed_records INTEGER NOT NULL,
            error_rate REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS log_records (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            timestamp TIMESTAMP,
            severity TEXT NOT NULL,
            service TEXT NOT NULL,
            message TEXT NOT NULL,
            exception_details TEXT,
            source_file TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            parsing_status TEXT NOT NULL,
            fingerprint TEXT,
            FOREIGN KEY (session_id) REFERENCES analysis_sessions (session_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS error_groups (
            group_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            normalized_template TEXT NOT NULL,
            severity TEXT NOT NULL,
            service TEXT NOT NULL,
            count INTEGER NOT NULL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            PRIMARY KEY (group_id, session_id),
            FOREIGN KEY (session_id) REFERENCES analysis_sessions (session_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            service TEXT NOT NULL,
            error_group_id TEXT NOT NULL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            occurrence_count INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            representative_evidence TEXT, -- JSON array string
            FOREIGN KEY (session_id) REFERENCES analysis_sessions (session_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ai_analyses (
            analysis_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            incident_summary TEXT NOT NULL,
            potential_root_causes_json TEXT NOT NULL,
            supporting_evidence_json TEXT NOT NULL,
            evidence_limitations_json TEXT NOT NULL,
            suggested_steps_json TEXT NOT NULL,
            potential_impact TEXT NOT NULL,
            confidence_explanation TEXT NOT NULL,
            source_log_references_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS monitoring_sessions (
            monitor_id TEXT PRIMARY KEY,
            file_path TEXT NOT NULL,
            status TEXT NOT NULL,
            last_offset INTEGER NOT NULL DEFAULT 0,
            records_processed INTEGER NOT NULL DEFAULT 0,
            errors_detected INTEGER NOT NULL DEFAULT 0,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            stopped_at TIMESTAMP
        );
    """)

    conn.commit()
    conn.close()
