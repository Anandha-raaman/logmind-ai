import logging
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

from database.db import get_db_connection
from logmind.models import (
    AIAnalysisReport,
    AnalysisSessionSummary,
    ErrorGroup,
    Incident,
    LogRecord,
    SeverityLevel,
)


def _parse_iso_dt(val: Optional[str]) -> Optional[datetime]:
    if not val or val.upper() in ("N/A", "NONE", "NULL"):
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None


class LogMindRepository:
    """Repository handling all CRUD database operations safely using parameterized queries."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path

    def save_analysis_session(
        self,
        summary: AnalysisSessionSummary,
        records: List[LogRecord],
        error_groups: Dict[str, ErrorGroup],
        incidents: List[Incident]
    ) -> None:
        """Save analysis session summary, log records, error groups, and incidents atomically and idempotently."""
        conn = get_db_connection(self.db_path)
        try:
            # Idempotency check: if session already exists, skip duplicate saving
            cursor = conn.cursor()
            cursor.execute("SELECT session_id FROM analysis_sessions WHERE session_id = ?", (summary.session_id,))
            if cursor.fetchone():
                return

            with conn:
                # 1. Insert analysis session
                conn.execute(
                    """
                    INSERT INTO analysis_sessions 
                    (session_id, filename, file_size_bytes, total_records, parsed_records, malformed_records, error_rate, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        summary.session_id,
                        summary.filename,
                        summary.file_size_bytes,
                        summary.total_records,
                        summary.parsed_records,
                        summary.malformed_records,
                        summary.error_rate,
                        summary.created_at.isoformat() if summary.created_at else datetime.utcnow().isoformat()
                    )
                )

                # 2. Insert log records (batch)
                seen_record_ids = set()
                record_tuples = []
                for r in records:
                    rec_id = r.id or str(uuid.uuid4())
                    if rec_id in seen_record_ids:
                        rec_id = str(uuid.uuid4())
                        r.id = rec_id
                    seen_record_ids.add(rec_id)
                    record_tuples.append((
                        rec_id,
                        summary.session_id,
                        r.timestamp.isoformat() if r.timestamp else None,
                        r.severity.value,
                        r.service,
                        r.message,
                        r.exception_details,
                        r.source_file,
                        r.line_number,
                        r.parsing_status.value,
                        r.fingerprint
                    ))
                if record_tuples:
                    conn.executemany(
                        """
                        INSERT INTO log_records 
                        (id, session_id, timestamp, severity, service, message, exception_details, source_file, line_number, parsing_status, fingerprint)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        record_tuples
                    )

                # 3. Insert error groups
                group_tuples = [
                    (
                        eg.group_id,
                        summary.session_id,
                        eg.normalized_template,
                        eg.severity.value,
                        eg.service,
                        eg.count,
                        eg.first_seen.isoformat() if eg.first_seen else None,
                        eg.last_seen.isoformat() if eg.last_seen else None
                    )
                    for eg in error_groups.values()
                ]
                if group_tuples:
                    conn.executemany(
                        """
                        INSERT INTO error_groups
                        (group_id, session_id, normalized_template, severity, service, count, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        group_tuples
                    )

                # 4. Insert incidents safely:
                #    Deduplicate in-memory batch incidents and check existing DB records to prevent UNIQUE constraint collisions.
                cursor.execute("SELECT incident_id FROM incidents")
                existing_db_inc_ids = {row[0] for row in cursor.fetchall()}

                seen_batch_original_ids = set()
                seen_all_inc_ids = set(existing_db_inc_ids)
                incident_tuples = []

                for inc in incidents:
                    orig_id = inc.incident_id

                    # Intra-batch duplicate check: skip duplicate incident records in the same batch
                    if orig_id in seen_batch_original_ids:
                        logger.warning(
                            "Duplicate incident_id '%s' detected in batch for session '%s'. Skipping duplicate batch entry.",
                            orig_id,
                            summary.session_id
                        )
                        continue
                    seen_batch_original_ids.add(orig_id)

                    # Ensure incident_id is unique across DB and current batch
                    target_inc_id = orig_id
                    if target_inc_id in seen_all_inc_ids:
                        target_inc_id = f"{orig_id}-{summary.session_id}"
                        if target_inc_id in seen_all_inc_ids:
                            target_inc_id = f"{orig_id}-{uuid.uuid4().hex[:6]}"
                    
                    inc.incident_id = target_inc_id
                    seen_all_inc_ids.add(target_inc_id)

                    incident_tuples.append((
                        target_inc_id,
                        summary.session_id,
                        inc.title,
                        inc.severity.value,
                        inc.service,
                        inc.error_group_id,
                        inc.first_seen.isoformat() if inc.first_seen else None,
                        inc.last_seen.isoformat() if inc.last_seen else None,
                        inc.occurrence_count,
                        inc.status,
                        json.dumps(inc.representative_evidence)
                    ))

                if incident_tuples:
                    conn.executemany(
                        """
                        INSERT INTO incidents
                        (incident_id, session_id, title, severity, service, error_group_id, first_seen, last_seen, occurrence_count, status, representative_evidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        incident_tuples
                    )
        except sqlite3.Error as e:
            raise RuntimeError(f"Database transaction failed while saving session '{summary.session_id}': {e}") from e
        finally:
            conn.close()

    def get_analysis_sessions(self, limit: int = 50) -> List[Dict]:
        """Fetch list of historical analysis sessions."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT session_id, filename, file_size_bytes, total_records, parsed_records, malformed_records, error_rate, created_at
                FROM analysis_sessions
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_session_by_id(self, session_id: str) -> Optional[Dict]:
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM analysis_sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_incidents_for_session(self, session_id: Optional[str] = None) -> List[Incident]:
        """Retrieve list of incidents, optionally filtered by session_id."""
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.cursor()
            if session_id:
                cursor.execute("SELECT * FROM incidents WHERE session_id = ? ORDER BY occurrence_count DESC", (session_id,))
            else:
                cursor.execute("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 100")
            
            rows = cursor.fetchall()
            incidents = []
            for row in rows:
                evidence = json.loads(row["representative_evidence"]) if row["representative_evidence"] else []
                ai_report = self.get_ai_analysis_for_incident(row["incident_id"])
                
                incidents.append(Incident(
                    incident_id=row["incident_id"],
                    title=row["title"],
                    severity=SeverityLevel.from_str(row["severity"]),
                    service=row["service"],
                    error_group_id=row["error_group_id"],
                    first_seen=_parse_iso_dt(row["first_seen"]),
                    last_seen=_parse_iso_dt(row["last_seen"]),
                    occurrence_count=row["occurrence_count"],
                    status=row["status"],
                    representative_evidence=evidence,
                    ai_analysis=ai_report
                ))
            return incidents
        finally:
            conn.close()

    def get_incident_by_id(self, incident_id: str) -> Optional[Incident]:
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None

            evidence = json.loads(row["representative_evidence"]) if row["representative_evidence"] else []
            ai_report = self.get_ai_analysis_for_incident(incident_id)

            return Incident(
                incident_id=row["incident_id"],
                title=row["title"],
                severity=SeverityLevel.from_str(row["severity"]),
                service=row["service"],
                error_group_id=row["error_group_id"],
                first_seen=_parse_iso_dt(row["first_seen"]),
                last_seen=_parse_iso_dt(row["last_seen"]),
                occurrence_count=row["occurrence_count"],
                status=row["status"],
                representative_evidence=evidence,
                ai_analysis=ai_report
            )
        finally:
            conn.close()

    def save_ai_analysis(self, incident_id: str, report: AIAnalysisReport) -> str:
        """Save AI analysis report associated with an incident."""
        conn = get_db_connection(self.db_path)
        analysis_id = f"ai-analysis-{str(uuid.uuid4())[:8]}"
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO ai_analyses
                    (analysis_id, incident_id, incident_summary, potential_root_causes_json, supporting_evidence_json, evidence_limitations_json, suggested_steps_json, potential_impact, confidence_explanation, source_log_references_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        analysis_id,
                        incident_id,
                        report.incident_summary,
                        json.dumps(report.potential_root_causes),
                        json.dumps(report.supporting_evidence),
                        json.dumps(report.evidence_limitations),
                        json.dumps(report.suggested_investigation_steps),
                        report.potential_impact,
                        report.confidence_explanation,
                        json.dumps(report.source_log_references)
                    )
                )
            return analysis_id
        finally:
            conn.close()

    def get_ai_analysis_for_incident(self, incident_id: str) -> Optional[AIAnalysisReport]:
        conn = get_db_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT incident_summary, potential_root_causes_json, supporting_evidence_json, evidence_limitations_json, suggested_steps_json, potential_impact, confidence_explanation, source_log_references_json
                FROM ai_analyses
                WHERE incident_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (incident_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            return AIAnalysisReport(
                incident_summary=row["incident_summary"],
                potential_root_causes=json.loads(row["potential_root_causes_json"]),
                supporting_evidence=json.loads(row["supporting_evidence_json"]),
                evidence_limitations=json.loads(row["evidence_limitations_json"]),
                suggested_investigation_steps=json.loads(row["suggested_steps_json"]),
                potential_impact=row["potential_impact"],
                confidence_explanation=row["confidence_explanation"],
                source_log_references=json.loads(row["source_log_references_json"])
            )
        finally:
            conn.close()

    def record_monitoring_start(self, monitor_id: str, file_path: str) -> None:
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO monitoring_sessions (monitor_id, file_path, status, started_at)
                    VALUES (?, ?, 'RUNNING', ?)
                    """,
                    (monitor_id, file_path, datetime.utcnow().isoformat())
                )
        finally:
            conn.close()

    def update_monitoring_checkpoint(self, monitor_id: str, last_offset: int, records_processed: int, errors_detected: int) -> None:
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    UPDATE monitoring_sessions
                    SET last_offset = ?, records_processed = ?, errors_detected = ?
                    WHERE monitor_id = ?
                    """,
                    (last_offset, records_processed, errors_detected, monitor_id)
                )
        finally:
            conn.close()

    def record_monitoring_stop(self, monitor_id: str) -> None:
        conn = get_db_connection(self.db_path)
        try:
            with conn:
                conn.execute(
                    """
                    UPDATE monitoring_sessions
                    SET status = 'STOPPED', stopped_at = ?
                    WHERE monitor_id = ?
                    """,
                    (datetime.utcnow().isoformat(), monitor_id)
                )
        finally:
            conn.close()
