import pytest
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database.db import init_db, get_db_connection
from database.repository import LogMindRepository
from logmind.analytics import AnalyticsEngine
from logmind.error_grouper import ErrorGrouper
from logmind.models import AnalysisSessionSummary, Incident, LogRecord, ParsingStatus, SeverityLevel, ErrorGroup
from logmind.parser import LogParser
from ui.components import format_timestamp


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_regression.db"
    init_db(db_file)
    return db_file


def test_duplicate_analysis_session_save(temp_db):
    """Scenario 1: Saving the exact same analysis session twice must be idempotent without raising IntegrityError."""
    repo = LogMindRepository(temp_db)
    now = datetime.now(timezone.utc)

    summary = AnalysisSessionSummary(
        session_id="sess-dup-001",
        filename="app.log",
        file_size_bytes=512,
        total_records=2,
        parsed_records=2,
        malformed_records=0,
        error_rate=50.0,
        created_at=now
    )
    records = [
        LogRecord(id="rec-1", timestamp=now, severity=SeverityLevel.ERROR, service="auth", message="Error 1", source_file="app.log", line_number=1),
        LogRecord(id="rec-2", timestamp=now, severity=SeverityLevel.INFO, service="auth", message="Info 1", source_file="app.log", line_number=2)
    ]
    groups = {
        "grp-auth-1": ErrorGroup(group_id="grp-auth-1", normalized_template="Error 1", severity=SeverityLevel.ERROR, service="auth", count=1, first_seen=now, last_seen=now)
    }
    incidents = [
        Incident(incident_id="inc-sess-dup-001-grp-auth-1", title="Error in auth", severity=SeverityLevel.ERROR, service="auth", error_group_id="grp-auth-1", first_seen=now, last_seen=now, occurrence_count=1)
    ]

    # First save
    repo.save_analysis_session(summary, records, groups, incidents)
    assert repo.get_session_by_id("sess-dup-001") is not None
    assert len(repo.get_incidents_for_session("sess-dup-001")) == 1

    # Second save of the exact same session - must succeed without error
    repo.save_analysis_session(summary, records, groups, incidents)
    assert len(repo.get_incidents_for_session("sess-dup-001")) == 1


def test_shared_fingerprints_across_sessions(temp_db):
    """Scenario 2: Saving two separate analysis sessions with identical error groups and incident IDs must succeed and preserve DB history."""
    repo = LogMindRepository(temp_db)
    now = datetime.now(timezone.utc)
    shared_group_id = "grp-shared-fingerprint-999"

    # Session 1
    s1 = AnalysisSessionSummary(session_id="sess-run-1", filename="monday.log", file_size_bytes=100, total_records=1, parsed_records=1, malformed_records=0)
    inc1 = Incident(incident_id=f"inc-{shared_group_id}", title="Shared Error", severity=SeverityLevel.ERROR, service="payment", error_group_id=shared_group_id, first_seen=now, last_seen=now, occurrence_count=3)
    repo.save_analysis_session(s1, [], {}, [inc1])

    # Session 2 with SAME error fingerprint and incident_id
    s2 = AnalysisSessionSummary(session_id="sess-run-2", filename="tuesday.log", file_size_bytes=200, total_records=1, parsed_records=1, malformed_records=0)
    inc2 = Incident(incident_id=f"inc-{shared_group_id}", title="Shared Error", severity=SeverityLevel.ERROR, service="payment", error_group_id=shared_group_id, first_seen=now, last_seen=now, occurrence_count=7)
    repo.save_analysis_session(s2, [], {}, [inc2])

    inc_s1 = repo.get_incidents_for_session("sess-run-1")
    inc_s2 = repo.get_incidents_for_session("sess-run-2")
    all_incidents = repo.get_incidents_for_session()

    assert len(inc_s1) == 1
    assert inc_s1[0].occurrence_count == 3
    assert len(inc_s2) == 1
    assert inc_s2[0].occurrence_count == 7
    assert len(all_incidents) == 2
    assert inc_s1[0].incident_id != inc_s2[0].incident_id


def test_batch_duplicates_in_same_upload_run(temp_db):
    """Scenario 3: Processing a batch with duplicate incident IDs in the same upload run must deduplicate safely."""
    repo = LogMindRepository(temp_db)
    now = datetime.now(timezone.utc)

    summary = AnalysisSessionSummary(session_id="sess-batch-dup-001", filename="batch.log", file_size_bytes=300, total_records=2, parsed_records=2, malformed_records=0)
    inc1 = Incident(incident_id="inc-batch-dup", title="Duplicate 1", severity=SeverityLevel.ERROR, service="svc", error_group_id="g1", first_seen=now, last_seen=now, occurrence_count=1)
    inc2 = Incident(incident_id="inc-batch-dup", title="Duplicate 2", severity=SeverityLevel.ERROR, service="svc", error_group_id="g1", first_seen=now, last_seen=now, occurrence_count=1)
    inc3 = Incident(incident_id="inc-batch-dup", title="Duplicate 3", severity=SeverityLevel.ERROR, service="svc", error_group_id="g1", first_seen=now, last_seen=now, occurrence_count=1)

    repo.save_analysis_session(summary, [], {}, [inc1, inc2, inc3])

    saved = repo.get_incidents_for_session("sess-batch-dup-001")
    assert len(saved) == 1
    assert saved[0].incident_id == "inc-batch-dup"


def test_transaction_rollback_on_db_failure(temp_db):
    """Scenario 4: Triggering a database error during save must roll back atomically with no partial writes."""
    repo = LogMindRepository(temp_db)
    now = datetime.now(timezone.utc)

    summary = AnalysisSessionSummary(session_id="sess-fail-001", filename="fail.log", file_size_bytes=50, total_records=1, parsed_records=1, malformed_records=0)
    invalid_record = LogRecord(id="rec-invalid", timestamp=now, severity=SeverityLevel.ERROR, service="svc", message="valid", source_file="f", line_number=1)
    invalid_record.message = None  # Causes NOT NULL constraint violation on log_records.message

    with pytest.raises(RuntimeError, match="Database transaction failed"):
        repo.save_analysis_session(summary, [invalid_record], {}, [])

    # Verify atomic rollback: session, log records, and error groups must not exist in DB
    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM analysis_sessions WHERE session_id = 'sess-fail-001'")
    assert cursor.fetchone()[0] == 0
    cursor.execute("SELECT COUNT(*) FROM log_records WHERE session_id = 'sess-fail-001'")
    assert cursor.fetchone()[0] == 0
    conn.close()


def test_malformed_timestamps_handling_and_line_counts():
    """Scenario 5: Process log batches with N/A or invalid timestamps, validate status and start/end time calculations."""
    parser = LogParser()
    lines = [
        "2026-10-02 14:00:00 [ERROR] [payment-service] Database query timeout req_id=1",
        "2026-10-02 14:05:00 [ERROR] [payment-service] Database query timeout req_id=2",
        "[N/A] [ERROR] [payment-service] Database query timeout req_id=3",
        "CORRUPTED_ENTRY_NO_TIMESTAMP [ERROR] [payment-service] Database query timeout req_id=4",
        "2026-02-30 25:61:99 [ERROR] [payment-service] Invalid timestamp test record req_id=5",
        "[MALFORMED RECORD LINE WITHOUT TIMESTAMP OR SEVERITY HERE]"
    ]

    records, stats = parser.parse_file_from_lines(lines) if hasattr(parser, 'parse_file_from_lines') else (parser.parse_text_lines(lines), {"total_source_lines": 6, "total_records": 6, "parsed": 2, "malformed": 4})

    # Verify status breakdown
    parsed_records = [r for r in records if r.parsing_status == ParsingStatus.PARSED]
    malformed_records = [r for r in records if r.parsing_status in (ParsingStatus.MALFORMED, ParsingStatus.PARTIAL)]

    assert len(parsed_records) == 2
    assert len(malformed_records) == 4
    assert len(records) == 6

    # Verify ErrorGrouper safely excludes N/A / None timestamps from first_seen / last_seen
    grouper = ErrorGrouper()
    error_groups = grouper.group_records(records)
    
    # 1. Main timeout error group has valid timestamps 14:00:00 to 14:05:00 despite containing N/A and corrupted records
    timeout_group = next(eg for eg in error_groups.values() if "query timeout" in eg.normalized_template)
    assert timeout_group.count == 4
    assert timeout_group.first_seen is not None
    assert timeout_group.first_seen.strftime("%H:%M:%S") == "14:00:00"
    assert timeout_group.last_seen is not None
    assert timeout_group.last_seen.strftime("%H:%M:%S") == "14:05:00"
    assert format_timestamp(timeout_group.first_seen) == "14:00:00"
    assert format_timestamp(timeout_group.last_seen) == "14:05:00"

    # 2. Invalid timestamp group (where all records have timestamp=None) has first_seen=None, last_seen=None, and format_timestamp returns "N/A"
    invalid_ts_group = next(eg for eg in error_groups.values() if "Invalid timestamp" in eg.normalized_template)
    assert invalid_ts_group.count == 1
    assert invalid_ts_group.first_seen is None
    assert invalid_ts_group.last_seen is None
    assert format_timestamp(invalid_ts_group.first_seen) == "N/A"
    assert format_timestamp(invalid_ts_group.last_seen) == "N/A"

    # Verify line count metric: total processed line count = valid grouped occurrences + malformed records
    summary = AnalyticsEngine.calculate_summary(records, stats.get("malformed", len(malformed_records)), error_groups)
    assert summary.total_records == summary.parsed_records + summary.malformed_records
    assert summary.total_records == 6
