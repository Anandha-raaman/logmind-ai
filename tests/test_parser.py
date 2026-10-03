import pytest
from logmind.parser import LogParser, parse_timestamp
from logmind.models import ParsingStatus, SeverityLevel


def test_parse_timestamp_iso():
    ts = parse_timestamp("2026-10-02T15:30:00Z")
    assert ts is not None
    assert ts.year == 2026
    assert ts.month == 10
    assert ts.day == 2
    assert ts.hour == 15


def test_parse_text_lines_valid():
    parser = LogParser(redact_secrets_enabled=False)
    lines = [
        "2026-10-02 14:00:00 [ERROR] [auth-service] Failed login attempt for user=admin",
        "2026-10-02 14:00:05 [INFO] [api-gateway] Request succeeded"
    ]
    records = parser.parse_text_lines(lines)
    assert len(records) == 2
    assert records[0].severity == SeverityLevel.ERROR
    assert records[0].service == "auth-service"
    assert "Failed login" in records[0].message
    assert records[1].severity == SeverityLevel.INFO


def test_parse_text_lines_multiline_exception():
    parser = LogParser()
    lines = [
        "2026-10-02 14:00:00 [ERROR] [payment-service] Gateway connection failed",
        "Traceback (most recent call last):",
        "  File 'gateway.py', line 12, in charge",
        "TimeoutError: Connection timed out"
    ]
    records = parser.parse_text_lines(lines)
    assert len(records) == 1
    assert records[0].exception_details is not None
    assert "TimeoutError" in records[0].exception_details


def test_parse_json_lines_valid():
    parser = LogParser()
    lines = [
        '{"timestamp": "2026-10-02T14:00:00Z", "level": "ERROR", "service": "db-cluster", "message": "Connection lost"}',
        '{"timestamp": "2026-10-02T14:00:05Z", "level": "INFO", "service": "user-service", "message": "User updated"}'
    ]
    records, malformed = parser.parse_json_lines(lines)
    assert len(records) == 2
    assert malformed == 0
    assert records[0].severity == SeverityLevel.ERROR
    assert records[0].service == "db-cluster"


def test_parse_json_lines_malformed():
    parser = LogParser()
    lines = [
        '{"timestamp": "2026-10-02T14:00:00Z", "level": "ERROR", "service": "db-cluster", "message": "Connection lost"}',
        'THIS IS NOT VALID JSON AT ALL'
    ]
    records, malformed = parser.parse_json_lines(lines)
    assert len(records) == 2
    assert malformed == 1
    assert records[1].parsing_status == ParsingStatus.MALFORMED


def test_parse_unicode_text():
    parser = LogParser()
    lines = ["2026-10-02 14:00:00 [ERROR] [service] Unicode test: 🔥 🚀 登录失败"]
    records = parser.parse_text_lines(lines)
    assert len(records) == 1
    assert "登录失败" in records[0].message


def test_parse_invalid_timestamp_line():
    parser = LogParser()
    lines = ["2026-02-30 25:61:99 [ERROR] [payment-service] Invalid timestamp test record"]
    records = parser.parse_text_lines(lines)
    assert len(records) == 1
    rec = records[0]
    assert rec.timestamp is None
    assert rec.parsing_status == ParsingStatus.MALFORMED
    assert rec.parsing_reason is not None
    assert "Invalid timestamp" in rec.parsing_reason


def test_parse_malformed_header_with_reason():
    parser = LogParser()
    lines = ["[MALFORMED RECORD LINE WITHOUT TIMESTAMP OR SEVERITY HERE]"]
    records = parser.parse_text_lines(lines)
    assert len(records) == 1
    rec = records[0]
    assert rec.timestamp is None
    assert rec.parsing_status in (ParsingStatus.MALFORMED, ParsingStatus.PARTIAL)
    assert rec.parsing_reason is not None

