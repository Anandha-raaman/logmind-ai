import pytest
from datetime import datetime
from logmind.error_grouper import ErrorGrouper, generate_fingerprint
from logmind.models import LogRecord, SeverityLevel


def test_generate_fingerprint_stability():
    fp1 = generate_fingerprint("auth-service", SeverityLevel.ERROR, "Failed login for [USER]")
    fp2 = generate_fingerprint("auth-service", SeverityLevel.ERROR, "Failed login for [USER]")
    assert fp1 == fp2
    assert len(fp1) == 16


def test_error_grouper_groups_identical_patterns():
    grouper = ErrorGrouper()
    r1 = LogRecord(
        service="payment-service",
        severity=SeverityLevel.ERROR,
        message="Payment timeout for order_id=1001",
        timestamp=datetime(2026, 10, 2, 14, 0, 0)
    )
    r2 = LogRecord(
        service="payment-service",
        severity=SeverityLevel.ERROR,
        message="Payment timeout for order_id=9942",
        timestamp=datetime(2026, 10, 2, 14, 0, 5)
    )

    groups = grouper.group_records([r1, r2])
    assert len(groups) == 1
    gid = list(groups.keys())[0]
    eg = groups[gid]
    assert eg.count == 2
    assert eg.service == "payment-service"
    assert eg.severity == SeverityLevel.ERROR


def test_error_grouper_does_not_merge_different_services_or_errors():
    grouper = ErrorGrouper()
    r1 = LogRecord(
        service="payment-service",
        severity=SeverityLevel.ERROR,
        message="Connection timeout to gateway",
    )
    r2 = LogRecord(
        service="user-service",
        severity=SeverityLevel.ERROR,
        message="Database query failed",
    )

    groups = grouper.group_records([r1, r2])
    assert len(groups) == 2
