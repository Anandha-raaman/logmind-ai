import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from config.settings import settings
from logmind.models import AnomalyEvent, ErrorGroup, LogRecord, SeverityLevel


class AnomalyDetector:
    """
    Statistical and rule-based anomaly detector for application logs.
    Identifies sudden error spikes, error rate jumps, and anomalous error groups.
    """

    def __init__(
        self,
        spike_threshold_std: float = settings.DEFAULT_SPIKE_THRESHOLD_STD,
        min_events_for_anomaly: int = settings.DEFAULT_MIN_EVENTS_FOR_ANOMALY,
        window_minutes: int = settings.DEFAULT_WINDOW_MINUTES
    ):
        self.spike_threshold_std = spike_threshold_std
        self.min_events_for_anomaly = min_events_for_anomaly
        self.window_minutes = window_minutes

    def detect_anomalies(
        self,
        records: List[LogRecord],
        error_groups: Dict[str, ErrorGroup]
    ) -> List[AnomalyEvent]:
        """
        Analyze log records and error groups to flag statistical anomalies and rule breaches.
        """
        anomalies: List[AnomalyEvent] = []
        
        # 1. Check overall dataset volume requirement
        total_errors = [r for r in records if r.severity in (SeverityLevel.ERROR, SeverityLevel.CRITICAL)]
        if len(records) < self.min_events_for_anomaly:
            # Insufficient data to claim statistical significance
            return anomalies

        # 2. Windowed Spike Detection
        windowed_anomalies = self._detect_window_spikes(records)
        anomalies.extend(windowed_anomalies)

        # 3. High-Frequency Error Group Anomalies
        group_anomalies = self._detect_dominant_error_groups(error_groups, total_records=len(records))
        anomalies.extend(group_anomalies)

        return anomalies

    def _detect_window_spikes(self, records: List[LogRecord]) -> List[AnomalyEvent]:
        """Detect rolling time-window error spikes using standard deviation Z-score."""
        anomalies: List[AnomalyEvent] = []
        records_with_ts = [r for r in records if r.timestamp is not None]
        if not records_with_ts:
            return anomalies

        # Bucket error counts by time window
        windows: Dict[datetime, int] = defaultdict(int)
        for r in records_with_ts:
            if r.severity in (SeverityLevel.ERROR, SeverityLevel.CRITICAL):
                # Floor timestamp to window interval
                ts = r.timestamp
                minute_bucket = (ts.minute // self.window_minutes) * self.window_minutes
                bucket_key = datetime(ts.year, ts.month, ts.day, ts.hour, minute_bucket)
                windows[bucket_key] += 1

        if len(windows) < 3:
            # Need at least 3 time windows to calculate mean/stddev
            return anomalies

        counts = list(windows.values())
        mean_count = sum(counts) / len(counts)
        variance = sum((x - mean_count) ** 2 for x in counts) / len(counts)
        std_dev = math.sqrt(variance)

        if std_dev == 0:
            return anomalies

        threshold = mean_count + (self.spike_threshold_std * std_dev)

        for bucket_ts, count in windows.items():
            if count >= self.min_events_for_anomaly and count > threshold:
                z_score = (count - mean_count) / std_dev
                anomalies.append(AnomalyEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=bucket_ts,
                    metric_name="window_error_count",
                    observed_value=float(count),
                    threshold_value=round(threshold, 2),
                    severity=SeverityLevel.CRITICAL if z_score > 3.5 else SeverityLevel.WARNING,
                    explanation=(
                        f"Suspicious error spike detected in {self.window_minutes}-minute window starting at {bucket_ts.strftime('%H:%M:%S')}. "
                        f"Observed {count} errors, exceeding baseline average ({mean_count:.1f} ± {std_dev:.1f}) by {z_score:.2f} std devs."
                    )
                ))

        return anomalies

    def _detect_dominant_error_groups(
        self,
        error_groups: Dict[str, ErrorGroup],
        total_records: int
    ) -> List[AnomalyEvent]:
        """Flag individual error groups accounting for an unusually large percentage of total errors."""
        anomalies: List[AnomalyEvent] = []
        
        for group_id, eg in error_groups.items():
            if eg.count >= self.min_events_for_anomaly:
                percentage = (eg.count / total_records) * 100.0
                # If a single error group accounts for > 25% of total log volume
                if percentage > 25.0:
                    anomalies.append(AnomalyEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=eg.last_seen or datetime.utcnow(),
                        metric_name="error_group_dominance",
                        observed_value=round(percentage, 1),
                        threshold_value=25.0,
                        severity=SeverityLevel.CRITICAL if percentage > 50.0 else SeverityLevel.WARNING,
                        explanation=(
                            f"Error group '{eg.normalized_template[:60]}...' in service '{eg.service}' is recurring intensely, "
                            f"representing {percentage:.1f}% ({eg.count} occurrences) of all processed records."
                        ),
                        affected_service=eg.service,
                        affected_error_group=group_id
                    ))

        return anomalies
