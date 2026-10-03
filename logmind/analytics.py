from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd

from logmind.models import ErrorGroup, LogRecord, SeverityLevel, ParsingStatus, AnalysisSessionSummary


class AnalyticsEngine:
    """Calculates summary statistics, time-series metrics, and service breakdowns."""

    @staticmethod
    def calculate_summary(
        records: List[LogRecord],
        malformed_count: int,
        error_groups: Dict[str, ErrorGroup],
        session_id: str = "session-1",
        filename: str = "unknown.log",
        file_size_bytes: int = 0,
        total_source_lines: int = 0
    ) -> AnalysisSessionSummary:
        actual_malformed = sum(1 for r in records if r.parsing_status == ParsingStatus.MALFORMED)
        parsed_records = sum(1 for r in records if r.parsing_status == ParsingStatus.PARSED)
        extra_malformed = max(0, malformed_count - actual_malformed)
        total_records = len(records) + extra_malformed
        actual_malformed += extra_malformed
        
        severity_counts = Counter(r.severity.value for r in records)
        if actual_malformed > 0:
            severity_counts["MALFORMED"] = actual_malformed

        error_count = severity_counts.get(SeverityLevel.ERROR.value, 0) + severity_counts.get(SeverityLevel.CRITICAL.value, 0)
        error_rate = (error_count / total_records * 100.0) if total_records > 0 else 0.0

        return AnalysisSessionSummary(
            session_id=session_id,
            filename=filename,
            file_size_bytes=file_size_bytes,
            total_source_lines=total_source_lines or len(records),
            total_records=total_records,
            parsed_records=parsed_records,
            malformed_records=actual_malformed,
            severity_counts=dict(severity_counts),
            error_rate=round(error_rate, 2),
            unique_error_groups=len(error_groups),
            anomalies_detected=0
        )

    @staticmethod
    def get_service_breakdown(records: List[LogRecord]) -> Dict[str, Dict[str, int]]:
        """Returns error and total count per service."""
        service_stats = defaultdict(lambda: {"total": 0, "errors": 0, "warnings": 0})
        for r in records:
            service_stats[r.service]["total"] += 1
            if r.severity in (SeverityLevel.ERROR, SeverityLevel.CRITICAL):
                service_stats[r.service]["errors"] += 1
            elif r.severity == SeverityLevel.WARNING:
                service_stats[r.service]["warnings"] += 1
        return dict(service_stats)

    @staticmethod
    def get_time_series_data(records: List[LogRecord], freq_minutes: int = 5) -> List[Dict[str, Any]]:
        """
        Groups log records into time buckets to generate time-series metrics for charts.
        """
        records_with_ts = [r for r in records if r.timestamp is not None]
        if not records_with_ts:
            return []

        # Create Pandas DataFrame for fast resampling
        data = [{
            "timestamp": r.timestamp,
            "is_error": 1 if r.severity in (SeverityLevel.ERROR, SeverityLevel.CRITICAL) else 0,
            "is_warning": 1 if r.severity == SeverityLevel.WARNING else 0,
            "total": 1
        } for r in records_with_ts]

        df = pd.DataFrame(data)
        df.set_index("timestamp", inplace=True)
        
        resampled = df.resample(f"{freq_minutes}min").sum().fillna(0)
        
        result = []
        for ts, row in resampled.iterrows():
            result.append({
                "timestamp": ts.isoformat(),
                "total_records": int(row["total"]),
                "error_count": int(row["is_error"]),
                "warning_count": int(row["is_warning"])
            })
            
        return result
