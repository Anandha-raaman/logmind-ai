import hashlib
from typing import Dict, List
from logmind.models import ErrorGroup, LogRecord, SeverityLevel
from logmind.normalizer import normalize_log_message


def generate_fingerprint(service: str, severity: SeverityLevel, normalized_template: str) -> str:
    """Generate a stable, deterministic MD5 fingerprint for log error grouping."""
    raw_key = f"{service.lower()}:{severity.value}:{normalized_template}"
    return hashlib.md5(raw_key.encode('utf-8')).hexdigest()[:16]


class ErrorGrouper:
    """Groups recurring error log records into deterministic error groups."""

    def __init__(self, max_representative_records: int = 5):
        self.max_representative_records = max_representative_records

    def group_records(self, records: List[LogRecord]) -> Dict[str, ErrorGroup]:
        """
        Group log records by service, severity, and normalized message structure.
        Returns a dictionary mapping group_id (fingerprint) to ErrorGroup.
        """
        groups: Dict[str, ErrorGroup] = {}

        for rec in records:
            # We group WARNING, ERROR, CRITICAL records primarily, but can group any non-info if required
            # Or group all records if needed. The specification states: "Group recurring errors".
            if rec.severity not in (SeverityLevel.ERROR, SeverityLevel.CRITICAL, SeverityLevel.WARNING, SeverityLevel.UNKNOWN):
                continue

            normalized_template = normalize_log_message(rec.message)
            if not normalized_template:
                normalized_template = "[EMPTY MESSAGE]"

            # Attach fingerprint to record for reference
            group_id = generate_fingerprint(rec.service, rec.severity, normalized_template)
            rec.fingerprint = group_id

            if group_id not in groups:
                groups[group_id] = ErrorGroup(
                    group_id=group_id,
                    normalized_template=normalized_template,
                    severity=rec.severity,
                    service=rec.service,
                    count=1,
                    first_seen=rec.timestamp,
                    last_seen=rec.timestamp,
                    representative_records=[rec]
                )
            else:
                eg = groups[group_id]
                eg.count += 1
                
                # Update timestamps
                if rec.timestamp:
                    if eg.first_seen is None or rec.timestamp < eg.first_seen:
                        eg.first_seen = rec.timestamp
                    if eg.last_seen is None or rec.timestamp > eg.last_seen:
                        eg.last_seen = rec.timestamp

                # Maintain representative evidence sample
                if len(eg.representative_records) < self.max_representative_records:
                    eg.representative_records.append(rec)

        return groups
