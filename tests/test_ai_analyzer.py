import pytest
from datetime import datetime
from logmind.ai_analyzer import AIIncidentAnalyzer
from logmind.models import Incident, SeverityLevel


def test_ai_analyzer_unconfigured_fallback():
    # Pass empty API key to test unconfigured fallback
    analyzer = AIIncidentAnalyzer(api_key="")
    assert analyzer.is_configured is False

    inc = Incident(
        incident_id="inc-test",
        title="Test Database Failure",
        severity=SeverityLevel.CRITICAL,
        service="db-service",
        error_group_id="grp-1",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        occurrence_count=5,
        status="OPEN",
        representative_evidence=["PostgreSQL connection pool exhausted"]
    )

    report = analyzer.analyze_incident(inc)
    assert report is not None
    assert "Gemini API key is not configured" in report.incident_summary
    assert len(report.potential_root_causes) > 0
    assert len(report.suggested_investigation_steps) > 0


def test_ai_analyzer_redacts_evidence():
    analyzer = AIIncidentAnalyzer(api_key="")
    inc = Incident(
        incident_id="inc-sec",
        title="Secret Test",
        severity=SeverityLevel.ERROR,
        service="auth",
        error_group_id="grp-sec",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        occurrence_count=1,
        representative_evidence=['Failed login password="my_secret_password_99"']
    )
    report = analyzer.analyze_incident(inc)
    for ev in report.supporting_evidence:
        assert "my_secret_password_99" not in ev
