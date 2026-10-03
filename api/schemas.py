from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from logmind.models import AIAnalysisReport, SeverityLevel


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    gemini_configured: bool
    db_status: str = "connected"


class FileAnalysisRequest(BaseModel):
    file_path: Optional[str] = None


class StartMonitorRequest(BaseModel):
    file_path: str = Field(..., description="Local path to authorized test log file")
    tail_from_end: bool = True


class MonitorStatusResponse(BaseModel):
    is_active: bool
    monitor_id: Optional[str] = None
    file_path: Optional[str] = None
    filename: Optional[str] = None
    records_processed: int = 0
    errors_detected: int = 0
    last_processed_timestamp: Optional[str] = None
    active_error_groups_count: int = 0
    detected_incidents_count: int = 0
    last_error_message: Optional[str] = None


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    severity: SeverityLevel
    service: str
    error_group_id: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    status: str
    representative_evidence: List[str]
    ai_analysis: Optional[AIAnalysisReport] = None


class ErrorResponse(BaseModel):
    detail: str
