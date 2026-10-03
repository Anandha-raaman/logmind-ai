import pytest
from datetime import datetime, timedelta
from logmind.anomaly_detector import AnomalyDetector
from logmind.models import ErrorGroup, LogRecord, SeverityLevel


def test_anomaly_detector_insufficient_data():
    detector = AnomalyDetector(min_events_for_anomaly=10)
    records = [LogRecord(severity=SeverityLevel.ERROR) for _ in range(3)]
    anomalies = detector.detect_anomalies(records, {})
    assert len(anomalies) == 0


def test_anomaly_detector_detects_spike():
    detector = AnomalyDetector(spike_threshold_std=1.5, min_events_for_anomaly=3, window_minutes=5)
    
    records = []
    base_time = datetime(2026, 10, 2, 14, 0, 0)
    
    # 3 baseline windows with 1 error each
    for w in range(3):
        ts = base_time + timedelta(minutes=w * 5)
        records.append(LogRecord(timestamp=ts, severity=SeverityLevel.ERROR, service="svc"))
        
    # 1 spike window with 20 errors
    spike_time = base_time + timedelta(minutes=15)
    for _ in range(20):
        records.append(LogRecord(timestamp=spike_time, severity=SeverityLevel.ERROR, service="svc"))

    groups = {"g1": ErrorGroup(group_id="g1", normalized_template="err", severity=SeverityLevel.ERROR, service="svc", count=23)}
    anomalies = detector.detect_anomalies(records, groups)
    assert len(anomalies) > 0
    spike_anom = [a for a in anomalies if a.metric_name == "window_error_count"]
    assert len(spike_anom) == 1
    assert spike_anom[0].observed_value == 20.0
