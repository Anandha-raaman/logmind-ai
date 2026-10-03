from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: str) -> "SeverityLevel":
        if not value:
            return cls.UNKNOWN
        val = value.upper().strip()
        if "CRIT" in val or "FATAL" in val:
            return cls.CRITICAL
        if "ERR" in val:
            return cls.ERROR
        if "WARN" in val:
            return cls.WARNING
        if "INFO" in val:
            return cls.INFO
        if "DBG" in val or "DEBUG" in val:
            return cls.DEBUG
        return cls.UNKNOWN


class ParsingStatus(str, Enum):
    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    MALFORMED = "MALFORMED"
    SKIPPED = "SKIPPED"


class LogRecord(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[datetime] = None
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    service: str = "unknown-service"
    message: str = ""
    exception_details: Optional[str] = None
    source_file: str = "unknown"
    line_number: int = 0
    parsing_status: ParsingStatus = ParsingStatus.PARSED
    parsing_reason: Optional[str] = None
    raw_content: Optional[str] = None
    fingerprint: Optional[str] = None


class ErrorGroup(BaseModel):
    group_id: str
    normalized_template: str
    severity: SeverityLevel
    service: str
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    representative_records: List[LogRecord] = Field(default_factory=list)


class AnomalyEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metric_name: str
    observed_value: float
    threshold_value: float
    severity: SeverityLevel = SeverityLevel.WARNING
    explanation: str
    affected_service: Optional[str] = None
    affected_error_group: Optional[str] = None


class AIAnalysisReport(BaseModel):
    incident_summary: str = Field(description="Summary of what occurred during the incident based on evidence")
    potential_root_causes: List[str] = Field(default_factory=list, description="Hypothesized root causes grounded in log evidence")
    supporting_evidence: List[str] = Field(default_factory=list, description="Specific log evidence supporting hypotheses")
    evidence_limitations: List[str] = Field(default_factory=list, description="Limitations or missing context in available evidence")
    suggested_investigation_steps: List[str] = Field(default_factory=list, description="Actionable next steps for engineers")
    potential_impact: str = Field(description="Estimated system or business impact", default="Unknown impact")
    confidence_explanation: str = Field(description="Explanation of confidence level and uncertainties")
    source_log_references: List[str] = Field(default_factory=list, description="References to key log records or timestamps")


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: SeverityLevel
    service: str
    error_group_id: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrence_count: int
    status: str = "OPEN"  # OPEN, INVESTIGATING, RESOLVED
    representative_evidence: List[str] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysisReport] = None


class AnalysisSessionSummary(BaseModel):
    session_id: str
    filename: str
    file_size_bytes: int
    total_source_lines: int = 0
    total_records: int
    parsed_records: int
    malformed_records: int
    created_at: datetime = Field(default_factory=datetime.utcnow)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    error_rate: float = 0.0
    unique_error_groups: int = 0
    anomalies_detected: int = 0
