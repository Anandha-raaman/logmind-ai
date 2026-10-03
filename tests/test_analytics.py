import pytest
from datetime import datetime
from logmind.analytics import AnalyticsEngine
from logmind.models import LogRecord, SeverityLevel, ErrorGroup


def test_calculate_summary():
    records = [
        LogRecord(severity=SeverityLevel.INFO, service="svc-a"),
        LogRecord(severity=SeverityLevel.ERROR, service="svc-a"),
        LogRecord(severity=SeverityLevel.CRITICAL, service="svc-b"),
        LogRecord(severity=SeverityLevel.WARNING, service="svc-b"),
    ]
    error_groups = {"g1": ErrorGroup(group_id="g1", normalized_template="t", severity=SeverityLevel.ERROR, service="svc-a")}
    summary = AnalyticsEngine.calculate_summary(records, malformed_count=1, error_groups=error_groups)

    assert summary.total_records == 5
    assert summary.parsed_records == 4
    assert summary.malformed_records == 1
    # 2 errors/critical out of 5 total = 40.0%
    assert summary.error_rate == 40.0
    assert summary.unique_error_groups == 1


def test_service_breakdown():
    records = [
        LogRecord(severity=SeverityLevel.ERROR, service="svc-a"),
        LogRecord(severity=SeverityLevel.ERROR, service="svc-a"),
        LogRecord(severity=SeverityLevel.INFO, service="svc-b"),
    ]
    breakdown = AnalyticsEngine.get_service_breakdown(records)
    assert breakdown["svc-a"]["errors"] == 2
    assert breakdown["svc-a"]["total"] == 2
    assert breakdown["svc-b"]["errors"] == 0
    assert breakdown["svc-b"]["total"] == 1


def test_time_series_data():
    ts1 = datetime(2026, 10, 2, 14, 0, 0)
    ts2 = datetime(2026, 10, 2, 14, 2, 0)
    records = [
        LogRecord(timestamp=ts1, severity=SeverityLevel.ERROR, service="s"),
        LogRecord(timestamp=ts2, severity=SeverityLevel.INFO, service="s"),
    ]
    ts_data = AnalyticsEngine.get_time_series_data(records, freq_minutes=5)
    assert len(ts_data) >= 1
    assert ts_data[0]["error_count"] == 1


def test_format_timestamp_utility():
    from ui.components import format_timestamp
    assert format_timestamp(None) == "N/A"
    assert format_timestamp(datetime(2026, 10, 2, 10, 1, 25)) == "10:01:25"
    assert format_timestamp("2026-10-02T10:00:01") == "10:00:01"
    assert format_timestamp("2026-10-02 10:00:01") == "10:00:01"
    assert format_timestamp("N/A") == "N/A"


def test_incident_table_data_structure():
    from logmind.models import Incident
    from ui.components import format_timestamp

    inc = Incident(
        incident_id="inc-test-123",
        title="ERROR in payment-service: Database connection timeout",
        severity=SeverityLevel.ERROR,
        service="payment-service",
        error_group_id="b9a80c32dc36f480",
        first_seen=datetime(2026, 10, 2, 10, 0, 1),
        last_seen=datetime(2026, 10, 2, 10, 1, 25),
        occurrence_count=8,
        status="OPEN"
    )

    row = {
        "incident_id": inc.incident_id,
        "severity": inc.severity.value,
        "service": inc.service,
        "occurrence_count": inc.occurrence_count,
        "message": inc.title,
        "first_seen": format_timestamp(inc.first_seen),
        "last_seen": format_timestamp(inc.last_seen)
    }

    assert row["incident_id"] == "inc-test-123"
    assert row["severity"] == "ERROR"
    assert row["service"] == "payment-service"
    assert row["occurrence_count"] == 8
    assert row["message"] == "ERROR in payment-service: Database connection timeout"
    assert row["first_seen"] == "10:00:01"
    assert row["last_seen"] == "10:01:25"

