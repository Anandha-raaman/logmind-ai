import os
import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks, status
from pathlib import Path

from config.settings import settings
from database.repository import LogMindRepository
from logmind.ai_analyzer import AIIncidentAnalyzer
from logmind.analytics import AnalyticsEngine
from logmind.anomaly_detector import AnomalyDetector
from logmind.error_grouper import ErrorGrouper
from logmind.monitoring_service import monitoring_service
from logmind.parser import LogParser
from logmind.models import AnalysisSessionSummary, Incident, SeverityLevel
from logmind.validators import validate_upload_content, validate_file_path, SecurityValidationError
from api.schemas import (
    HealthResponse,
    StartMonitorRequest,
    MonitorStatusResponse,
    IncidentResponse,
    ErrorResponse
)

router = APIRouter()
repository = LogMindRepository()
ai_analyzer = AIIncidentAnalyzer()


@router.get("/health", response_model=HealthResponse)
def get_health():
    """Health check endpoint displaying system state and Gemini API status."""
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        gemini_configured=settings.is_gemini_configured,
        db_status="connected"
    )


@router.post("/api/v1/analyses", status_code=status.HTTP_201_CREATED)
async def create_log_analysis(file: UploadFile = File(...)):
    """
    Upload and analyze a log file (.log, .txt, .json).
    Performs parsing, error grouping, analytics, and anomaly detection.
    """
    content = await file.read()
    is_valid, msg = validate_upload_content(file.filename, content)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    # Save temp upload file securely
    temp_dir = Path("data/uploads")
    temp_dir.mkdir(parents=True, exist_ok=True)
    session_id = f"sess-{str(uuid.uuid4())[:8]}"
    save_path = temp_dir / f"{session_id}_{Path(file.filename).name}"

    with open(save_path, "wb") as f:
        f.write(content)

    # Core Log Processing
    parser = LogParser()
    records, stats = parser.parse_file(save_path)

    grouper = ErrorGrouper()
    error_groups = grouper.group_records(records)

    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(records, error_groups)

    summary = AnalyticsEngine.calculate_summary(
        records=records,
        malformed_count=stats["malformed"],
        error_groups=error_groups,
        session_id=session_id,
        filename=file.filename,
        file_size_bytes=len(content),
        total_source_lines=stats.get("total_source_lines", stats.get("total", 0))
    )
    summary.anomalies_detected = len(anomalies)

    # Build Incidents
    incidents: List[Incident] = []
    for gid, eg in error_groups.items():
        if eg.count >= 2:
            inc_id = f"inc-{session_id}-{gid}"
            incidents.append(Incident(
                incident_id=inc_id,
                title=f"{eg.severity.value} in {eg.service}: {eg.normalized_template[:60]}",
                severity=eg.severity,
                service=eg.service,
                error_group_id=gid,
                first_seen=eg.first_seen,
                last_seen=eg.last_seen,
                occurrence_count=eg.count,
                status="OPEN",
                representative_evidence=[r.message for r in eg.representative_records[:3]]
            ))

    # Persist to SQLite
    repository.save_analysis_session(summary, records, error_groups, incidents)

    # Clean up temp file
    if save_path.exists():
        save_path.unlink()

    return {
        "session_summary": summary.model_dump(),
        "error_groups_count": len(error_groups),
        "anomalies_count": len(anomalies),
        "incidents_count": len(incidents),
        "incidents": [inc.model_dump() for inc in incidents]
    }


@router.get("/api/v1/analyses/{analysis_id}")
def get_analysis_session(analysis_id: str):
    """Retrieve historical analysis session by ID."""
    session = repository.get_session_by_id(analysis_id)
    if not session:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    incidents = repository.get_incidents_for_session(analysis_id)
    return {
        "session": session,
        "incidents": [inc.model_dump() for inc in incidents]
    }


@router.get("/api/v1/incidents", response_model=List[IncidentResponse])
def list_incidents(session_id: Optional[str] = None):
    """List detected incidents across sessions or for a specific session."""
    incidents = repository.get_incidents_for_session(session_id)
    return [inc.model_dump() for inc in incidents]


@router.get("/api/v1/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident_detail(incident_id: str):
    """Get detailed information for a specific incident."""
    incident = repository.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return incident.model_dump()


@router.post("/api/v1/incidents/{incident_id}/analyze")
def trigger_ai_incident_analysis(incident_id: str):
    """Trigger GenAI analysis for an incident using evidence grounding."""
    incident = repository.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    report = ai_analyzer.analyze_incident(incident)
    repository.save_ai_analysis(incident_id, report)
    incident.ai_analysis = report

    return {
        "message": "AI analysis completed successfully.",
        "incident_id": incident_id,
        "report": report.model_dump()
    }


@router.get("/api/v1/monitor/status", response_model=MonitorStatusResponse)
def get_monitor_status():
    """Get status of the real-time local log file monitor."""
    return MonitorStatusResponse(**monitoring_service.get_status())


@router.post("/api/v1/monitor/start")
def start_monitor(req: StartMonitorRequest):
    """Start real-time monitoring on an authorized local test log file."""
    res = monitoring_service.start_monitoring(req.file_path, tail_from_end=req.tail_from_end)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res


@router.post("/api/v1/monitor/stop")
def stop_monitor():
    """Stop active real-time log monitor."""
    res = monitoring_service.stop_monitoring()
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message"))
    return res
