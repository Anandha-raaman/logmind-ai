import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from logmind.models import LogRecord, ParsingStatus, SeverityLevel
from logmind.normalizer import redact_secrets, normalize_log_message

# Common timestamp patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601: 2026-10-02T15:30:00.123Z or 2026-10-02 15:30:00,123
    (re.compile(r'\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[\.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b'), '%Y-%m-%dT%H:%M:%S'),
    # Standard date time: 2026-10-02 15:30:00
    (re.compile(r'\b(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\b'), '%Y/%m/%d %H:%M:%S'),
    # Syslog / Apache format: Oct 02 15:30:00 or 02/Oct/2026:15:30:00
    (re.compile(r'\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b'), '%b %d %H:%M:%S'),
]

# Common log line pattern: [Timestamp] [Severity] [Service] Message
TEXT_LOG_REGEX = re.compile(
    r'^(?:\[?(?P<timestamp>\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[\.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|N/A|\[N/A\]|CORRUPTED[A-Z_]*|NO_TIMESTAMP|INVALID_TIMESTAMP|MISSING_TIMESTAMP)\]?\s+)?'
    r'(?:\[?(?P<severity>CRITICAL|FATAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|DBG)\]?\s+)?'
    r'(?:\[?(?P<service>[a-zA-Z0-9_\-\.]+):?\]?\s+)?'
    r'(?P<message>.*)$',
    re.IGNORECASE
)


def parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse various timestamp strings safely with year bounds checking."""
    if not ts_str:
        return None
    
    clean_ts = ts_str.strip("[]'\"")
    # Clean ISO comma millisecond
    clean_ts = clean_ts.replace(',', '.')
    
    dt = None
    # Try standard Python datetime fromisoformat (Python 3.11+)
    try:
        # Handle trailing Z
        iso_str = clean_ts.replace('Z', '+00:00')
        if 'T' not in iso_str and ' ' in iso_str:
            iso_str = iso_str.replace(' ', 'T', 1)
        dt = datetime.fromisoformat(iso_str)
    except Exception:
        pass

    if not dt:
        # Fallback pattern parsing
        for pattern, fmt in TIMESTAMP_PATTERNS:
            match = pattern.search(clean_ts)
            if match:
                matched_str = match.group(1)
                # Normalize for strptime
                matched_str = matched_str.split('.')[0].replace('T', ' ')
                try:
                    dt = datetime.strptime(matched_str, "%Y-%m-%d %H:%M:%S")
                    break
                except Exception:
                    try:
                        dt = datetime.strptime(matched_str, "%Y/%m/%d %H:%M:%S")
                        break
                    except Exception:
                        pass

    if dt:
        # Bounds validation
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt

    return None


class LogParser:
    """Robust log parser supporting Plain-Text and JSON log formats."""

    def __init__(self, default_service: str = "app-service", redact_secrets_enabled: bool = True):
        self.default_service = default_service
        self.redact_secrets_enabled = redact_secrets_enabled

    def parse_text_lines(self, lines: List[str], source_file: str = "text.log") -> List[LogRecord]:
        """Parse plain text log lines with multiline stack trace support."""
        records: List[LogRecord] = []
        current_record: Optional[LogRecord] = None
        exception_buffer: List[str] = []

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip('\r\n')
            if not line.strip():
                continue

            # Check if line looks like a new log entry
            is_new_entry = self._is_new_log_entry(line)

            if is_new_entry:
                # Flush previous record if existing
                if current_record:
                    if exception_buffer:
                        current_record.exception_details = "\n".join(exception_buffer)
                        exception_buffer = []
                    records.append(current_record)

                current_record = self._parse_single_text_line(line, line_num, source_file)
            else:
                # Append to multiline exception buffer or existing record message
                if current_record:
                    exception_buffer.append(line)
                else:
                    # Line without header before any record
                    records.append(LogRecord(
                        id=str(uuid.uuid4()),
                        message=redact_secrets(line) if self.redact_secrets_enabled else line,
                        severity=SeverityLevel.UNKNOWN,
                        service=self.default_service,
                        source_file=source_file,
                        line_number=line_num,
                        parsing_status=ParsingStatus.PARTIAL,
                        raw_content=line
                    ))

        if current_record:
            if exception_buffer:
                current_record.exception_details = "\n".join(exception_buffer)
            records.append(current_record)

        return records

    def _is_new_log_entry(self, line: str) -> bool:
        """Determine if a line is the start of a new log entry."""
        # Lines starting with whitespace, Traceback, at, Caused by, or Exception class names are stacktrace continuations
        if line.startswith((' ', '\t', 'Traceback', 'at ', 'Caused by:', 'File "')) or re.match(r'^[a-zA-Z0-9_\.]+(Error|Exception):', line):
            return False
        
        # Check if line matches timestamp pattern or severity tag
        if re.search(r'^\s*\[?\d{4}[-/.]\d{2}[-/.]\d{2}', line) or re.search(r'^\s*\[?(CRITICAL|FATAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|DBG)\]?', line, re.I):
            return True
            
        return True

    def _parse_single_text_line(self, line: str, line_num: int, source_file: str) -> LogRecord:
        record_id = str(uuid.uuid4())
        cleaned_line = redact_secrets(line) if self.redact_secrets_enabled else line

        match = TEXT_LOG_REGEX.match(line)
        if not match:
            return LogRecord(
                id=record_id,
                message=cleaned_line,
                severity=SeverityLevel.UNKNOWN,
                service=self.default_service,
                source_file=source_file,
                line_number=line_num,
                parsing_status=ParsingStatus.MALFORMED,
                parsing_reason="Unrecognized log line format (missing timestamp or severity header)",
                raw_content=line
            )

        groups = match.groupdict()
        raw_ts = groups.get("timestamp")
        ts = parse_timestamp(raw_ts)
        severity = SeverityLevel.from_str(groups.get("severity") or "")
        service = groups.get("service") or self.default_service
        msg = (groups.get("message") or "").strip()
        
        if self.redact_secrets_enabled:
            msg = redact_secrets(msg)

        parsing_status = ParsingStatus.PARSED
        parsing_reason = None

        corrupt_token_match = any(token in line for token in ("CORRUPTED_ENTRY", "NO_TIMESTAMP", "INVALID_TIMESTAMP", "MISSING_TIMESTAMP")) or line.strip().startswith(("[N/A]", "N/A"))

        if raw_ts and not ts:
            parsing_status = ParsingStatus.MALFORMED
            parsing_reason = f"Invalid timestamp format or out-of-range value: '{raw_ts}'"
        elif corrupt_token_match:
            parsing_status = ParsingStatus.MALFORMED
            parsing_reason = f"Corrupted or missing timestamp entry in line: '{line[:60]}'"
        elif not ts:
            parsing_status = ParsingStatus.MALFORMED
            parsing_reason = f"Missing valid timestamp in log entry: '{line[:60]}'"
        elif severity == SeverityLevel.UNKNOWN:
            parsing_status = ParsingStatus.PARTIAL
            parsing_reason = "Missing recognized severity level"

        return LogRecord(
            id=record_id,
            timestamp=ts,
            severity=severity,
            service=service,
            message=msg,
            source_file=source_file,
            line_number=line_num,
            parsing_status=parsing_status,
            parsing_reason=parsing_reason,
            raw_content=line
        )

    def parse_json_lines(self, lines: List[str], source_file: str = "json.log") -> Tuple[List[LogRecord], int]:
        """Parse JSON formatted log lines."""
        records: List[LogRecord] = []
        malformed_count = 0

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    malformed_count += 1
                    records.append(LogRecord(
                        id=str(uuid.uuid4()),
                        message=redact_secrets(line) if self.redact_secrets_enabled else line,
                        severity=SeverityLevel.UNKNOWN,
                        service=self.default_service,
                        source_file=source_file,
                        line_number=line_num,
                        parsing_status=ParsingStatus.MALFORMED,
                        parsing_reason="JSON root is not a dictionary object",
                        raw_content=line
                    ))
                    continue

                # Flexible field extraction
                ts_str = str(data.get("timestamp") or data.get("time") or data.get("@timestamp") or data.get("date") or "")
                ts = parse_timestamp(ts_str) if ts_str else None

                sev_str = str(data.get("severity") or data.get("level") or data.get("log.level") or data.get("loglevel") or "")
                severity = SeverityLevel.from_str(sev_str)

                service = str(data.get("service") or data.get("app") or data.get("module") or data.get("service_name") or self.default_service)
                message = str(data.get("message") or data.get("msg") or data.get("log") or data.get("error") or "")
                
                if self.redact_secrets_enabled:
                    message = redact_secrets(message)

                exc = data.get("stack_trace") or data.get("exception") or data.get("trace") or data.get("exc_info")
                exc_str = str(exc) if exc else None
                if exc_str and self.redact_secrets_enabled:
                    exc_str = redact_secrets(exc_str)

                parsing_status = ParsingStatus.PARSED
                parsing_reason = None

                corrupt_token_match = any(token in line for token in ("CORRUPTED_ENTRY", "NO_TIMESTAMP", "INVALID_TIMESTAMP", "MISSING_TIMESTAMP")) or line.strip().startswith(("[N/A]", "N/A"))

                if ts_str and not ts:
                    parsing_status = ParsingStatus.MALFORMED
                    parsing_reason = f"Invalid timestamp value in JSON field: '{ts_str}'"
                    malformed_count += 1
                elif corrupt_token_match:
                    parsing_status = ParsingStatus.MALFORMED
                    parsing_reason = f"Corrupted or missing timestamp entry in JSON line: '{line[:60]}'"
                    malformed_count += 1
                elif not ts:
                    parsing_status = ParsingStatus.MALFORMED
                    parsing_reason = "Missing timestamp field in JSON log record"
                    malformed_count += 1

                records.append(LogRecord(
                    id=str(uuid.uuid4()),
                    timestamp=ts,
                    severity=severity,
                    service=service,
                    message=message,
                    exception_details=exc_str,
                    source_file=source_file,
                    line_number=line_num,
                    parsing_status=parsing_status,
                    parsing_reason=parsing_reason,
                    raw_content=line
                ))

            except Exception as e:
                malformed_count += 1
                records.append(LogRecord(
                    id=str(uuid.uuid4()),
                    message=redact_secrets(line) if self.redact_secrets_enabled else line,
                    severity=SeverityLevel.UNKNOWN,
                    service=self.default_service,
                    source_file=source_file,
                    line_number=line_num,
                    parsing_status=ParsingStatus.MALFORMED,
                    parsing_reason=f"Invalid JSON syntax: {str(e)}",
                    raw_content=line
                ))

        return records, malformed_count

    def parse_file(self, file_path: Union[str, Path]) -> Tuple[List[LogRecord], Dict[str, int]]:
        """Parse log file automatically detecting JSON vs Text format."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        total_source_lines = len(lines)
        if total_source_lines == 0:
            return [], {"total_source_lines": 0, "total_records": 0, "parsed": 0, "malformed": 0}

        # Sample first few non-empty lines to detect JSON format
        sample_json = False
        for line in lines[:10]:
            sline = line.strip()
            if sline.startswith("{") and sline.endswith("}"):
                try:
                    json.loads(sline)
                    sample_json = True
                    break
                except Exception:
                    pass

        if sample_json or path.suffix.lower() == ".json":
            records, malformed = self.parse_json_lines(lines, source_file=path.name)
        else:
            records = self.parse_text_lines(lines, source_file=path.name)
            malformed = sum(1 for r in records if r.parsing_status != ParsingStatus.PARSED)

        parsed_count = sum(1 for r in records if r.parsing_status == ParsingStatus.PARSED)
        stats = {
            "total_source_lines": total_source_lines,
            "total_records": len(records),
            "parsed": parsed_count,
            "malformed": malformed
        }
        return records, stats
