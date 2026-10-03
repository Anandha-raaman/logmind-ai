import pytest
import sqlite3
from datetime import datetime
from pathlib import Path
from database.db import init_db, get_db_connection
from database.repository import LogMindRepository
from logmind.models import AnalysisSessionSummary, Incident, LogRecord, SeverityLevel, ErrorGroup


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_logmind.db"
    init_db(db_file)
    return db_file


def test_db_foreign_keys_enforced(temp_db):
    conn = get_db_connection(temp_db)
    # Attempting to insert log record with invalid session_id should raise IntegrityError
    with pytest.raises(sqlite3.IntegrityError):
        with conn:
            conn.execute(
                """
                INSERT INTO log_records 
                (id, session_id, severity, service, message, source_file, line_number, parsing_status)
                VALUES ('rec-1', 'non-existent-session', 'ERROR', 'svc', 'msg', 'file.log', 1, 'PARSED')
                """
            )
    conn.close()


def test_repository_save_and_retrieve_session(temp_db):
    repo = LogMindRepository(temp_db)
    
    summary = AnalysisSessionSummary(
        session_id="sess-100",
        filename="app.log",
        file_size_bytes=1024,
        total_records=10,
        parsed_records=9,
        malformed_records=1,
        error_rate=20.0,
        created_at=datetime.utcnow()
    )
    
    records = [
        LogRecord(id="rec-100", timestamp=datetime.utcnow(), severity=SeverityLevel.ERROR, service="auth", message="Error 1", source_file="app.log", line_number=1)
    ]
    
    error_groups = {
        "grp-1": ErrorGroup(group_id="grp-1", normalized_template="Error 1", severity=SeverityLevel.ERROR, service="auth", count=1)
    }
    
    incidents = [
        Incident(
            incident_id="inc-1",
            title="Error in auth",
            severity=SeverityLevel.ERROR,
            service="auth",
            error_group_id="grp-1",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            occurrence_count=1,
            status="OPEN"
        )
    ]
    
    repo.save_analysis_session(summary, records, error_groups, incidents)

    saved_sess = repo.get_session_by_id("sess-100")
    assert saved_sess is not None
    assert saved_sess["filename"] == "app.log"
    assert saved_sess["error_rate"] == 20.0

    retrieved_incidents = repo.get_incidents_for_session("sess-100")
    assert len(retrieved_incidents) == 1
    assert retrieved_incidents[0].incident_id == "inc-1"


def test_save_same_analysis_twice_idempotency(temp_db):
    """Saving the exact same session twice should be idempotent without IntegrityError."""
    repo = LogMindRepository(temp_db)
    summary = AnalysisSessionSummary(session_id="sess-dup", filename="a.log", file_size_bytes=100, total_records=1, parsed_records=1, malformed_records=0)
    records = [LogRecord(id="r-1", message="Err", severity=SeverityLevel.ERROR)]
    groups = {"g-1": ErrorGroup(group_id="g-1", normalized_template="Err", severity=SeverityLevel.ERROR, service="svc")}
    incidents = [Incident(incident_id="inc-dup-g1", title="Err", severity=SeverityLevel.ERROR, service="svc", error_group_id="g-1", first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=1)]

    # First save
    repo.save_analysis_session(summary, records, groups, incidents)
    assert repo.get_session_by_id("sess-dup") is not None

    # Second save of same session - must not raise IntegrityError
    repo.save_analysis_session(summary, records, groups, incidents)
    assert len(repo.get_incidents_for_session("sess-dup")) == 1


def test_save_two_sessions_same_error_group(temp_db):
    """Saving two separate analysis sessions with the same error group must succeed and preserve history."""
    repo = LogMindRepository(temp_db)
    error_group_id = "g-shared-123"

    # Session 1
    s1 = AnalysisSessionSummary(session_id="sess-001", filename="a.log", file_size_bytes=100, total_records=1, parsed_records=1, malformed_records=0)
    inc1 = Incident(incident_id="inc-sess-001-gshared", title="Shared Error", severity=SeverityLevel.ERROR, service="payment", error_group_id=error_group_id, first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=5)
    repo.save_analysis_session(s1, [], {}, [inc1])

    # Session 2 with SAME error group
    s2 = AnalysisSessionSummary(session_id="sess-002", filename="b.log", file_size_bytes=200, total_records=1, parsed_records=1, malformed_records=0)
    inc2 = Incident(incident_id="inc-sess-002-gshared", title="Shared Error", severity=SeverityLevel.ERROR, service="payment", error_group_id=error_group_id, first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=10)
    repo.save_analysis_session(s2, [], {}, [inc2])

    inc_s1 = repo.get_incidents_for_session("sess-001")
    inc_s2 = repo.get_incidents_for_session("sess-002")
    all_incidents = repo.get_incidents_for_session()

    assert len(inc_s1) == 1
    assert inc_s1[0].occurrence_count == 5
    assert len(inc_s2) == 1
    assert inc_s2[0].occurrence_count == 10
    assert len(all_incidents) == 2


def test_save_batch_with_duplicate_incident_ids(temp_db):
    """Verify that a batch containing duplicate incident IDs is deduplicated safely without raising IntegrityError."""
    repo = LogMindRepository(temp_db)
    summary = AnalysisSessionSummary(session_id="sess-batch-dup", filename="batch_dup.log", file_size_bytes=100, total_records=2, parsed_records=2, malformed_records=0)
    inc1 = Incident(incident_id="inc-dup-batch", title="Duplicate 1", severity=SeverityLevel.ERROR, service="svc", error_group_id="g1", first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=1)
    inc2 = Incident(incident_id="inc-dup-batch", title="Duplicate 2", severity=SeverityLevel.ERROR, service="svc", error_group_id="g1", first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=1)

    # Should succeed safely without IntegrityError
    repo.save_analysis_session(summary, [], {}, [inc1, inc2])

    saved_incidents = repo.get_incidents_for_session("sess-batch-dup")
    assert len(saved_incidents) == 1
    assert saved_incidents[0].incident_id == "inc-dup-batch"


def test_save_two_sessions_different_error_groups(temp_db):
    """Verify that saving two sessions with different incident groups keeps them completely separate."""
    repo = LogMindRepository(temp_db)
    s1 = AnalysisSessionSummary(session_id="sess-alpha", filename="a.log", file_size_bytes=100, total_records=1, parsed_records=1, malformed_records=0)
    inc1 = Incident(incident_id="inc-alpha-g1", title="Alpha Error", severity=SeverityLevel.ERROR, service="auth", error_group_id="g-alpha", first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=2)
    repo.save_analysis_session(s1, [], {}, [inc1])

    s2 = AnalysisSessionSummary(session_id="sess-beta", filename="b.log", file_size_bytes=200, total_records=1, parsed_records=1, malformed_records=0)
    inc2 = Incident(incident_id="inc-beta-g2", title="Beta Error", severity=SeverityLevel.CRITICAL, service="payment", error_group_id="g-beta", first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), occurrence_count=4)
    repo.save_analysis_session(s2, [], {}, [inc2])

    inc_s1 = repo.get_incidents_for_session("sess-alpha")
    inc_s2 = repo.get_incidents_for_session("sess-beta")

    assert len(inc_s1) == 1
    assert inc_s1[0].incident_id == "inc-alpha-g1"
    assert len(inc_s2) == 1
    assert inc_s2[0].incident_id == "inc-beta-g2"
    assert inc_s1[0].error_group_id != inc_s2[0].error_group_id


def test_transaction_rollback_on_failure(temp_db):
    """Verify that an invalid database operation inside save_analysis_session rolls back atomically."""
    repo = LogMindRepository(temp_db)
    summary = AnalysisSessionSummary(session_id="sess-fail", filename="fail.log", file_size_bytes=50, total_records=1, parsed_records=1, malformed_records=0)

    # Force a sqlite3.Error inside save_analysis_session (e.g. log_record with message=None violating NOT NULL)
    invalid_record = LogRecord(id="rec-fail", timestamp=datetime.utcnow(), severity=SeverityLevel.ERROR, service="svc", message="valid", source_file="f", line_number=1)
    invalid_record.message = None  # NOT NULL constraint on log_records.message

    with pytest.raises(RuntimeError, match="Database transaction failed"):
        repo.save_analysis_session(summary, [invalid_record], {}, [])

    # Ensure session was rolled back atomically and not persisted partially
    assert repo.get_session_by_id("sess-fail") is None




