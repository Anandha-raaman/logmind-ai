import logging
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from database.repository import LogMindRepository
from logmind.anomaly_detector import AnomalyDetector
from logmind.error_grouper import ErrorGrouper
from logmind.log_collector import FileTailCollector
from logmind.models import AnomalyEvent, ErrorGroup, Incident, LogRecord, SeverityLevel
from logmind.parser import LogParser
from logmind.validators import validate_file_path, SecurityValidationError

logger = logging.getLogger(__name__)


class MonitoringService:
    """
    Thread-safe real-time local log monitoring service.
    Tails a local log file, processes appends in real time, and updates incident metrics.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MonitoringService, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, repository: Optional[LogMindRepository] = None):
        if self._initialized:
            return
        
        self.repository = repository or LogMindRepository()
        self.parser = LogParser()
        self.grouper = ErrorGrouper()
        self.anomaly_detector = AnomalyDetector()

        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # State & Metrics
        self.monitor_id: Optional[str] = None
        self.target_file_path: Optional[Path] = None
        self.is_active: bool = False
        self.last_processed_timestamp: Optional[datetime] = None
        self.records_processed: int = 0
        self.errors_detected: int = 0
        self.last_error_message: Optional[str] = None

        # Data Stores
        self.recent_logs: deque[LogRecord] = deque(maxlen=200)
        self.active_error_groups: Dict[str, ErrorGroup] = {}
        self.detected_anomalies: List[AnomalyEvent] = []
        self.detected_incidents: Dict[str, Incident] = {}

        self._initialized = True

    def start_monitoring(self, file_path: str, tail_from_end: bool = True) -> Dict:
        """Start background thread monitoring for the specified file."""
        with self._lock:
            if self.is_active:
                return {
                    "success": False,
                    "message": f"Monitoring is already active on '{self.target_file_path}'"
                }

            try:
                validated_path = validate_file_path(file_path)
            except SecurityValidationError as e:
                return {"success": False, "message": str(e)}

            self.target_file_path = validated_path
            self.monitor_id = f"mon-{str(uuid.uuid4())[:8]}"
            self._stop_event.clear()

            # Initialize Tail Collector
            collector = FileTailCollector(validated_path)
            if tail_from_end:
                collector.seek_to_end()
            else:
                collector.seek_to_beginning()

            # Reset metrics
            self.records_processed = 0
            self.errors_detected = 0
            self.recent_logs.clear()
            self.active_error_groups.clear()
            self.detected_anomalies.clear()
            self.detected_incidents.clear()
            self.last_error_message = None

            # Spawn worker thread
            self.is_active = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                args=(collector,),
                daemon=True,
                name="LogMind-MonitorThread"
            )
            self._monitor_thread.start()

            # Record in repository
            try:
                self.repository.record_monitoring_start(self.monitor_id, str(validated_path))
            except Exception as e:
                logger.warning(f"Could not record monitoring start in DB: {e}")

            return {
                "success": True,
                "message": f"Started real-time monitoring on '{validated_path.name}'",
                "monitor_id": self.monitor_id
            }

    def stop_monitoring(self) -> Dict:
        """Gracefully stop the background monitoring thread."""
        with self._lock:
            if not self.is_active:
                return {"success": False, "message": "Monitoring service is not currently active."}

            self._stop_event.set()
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=3.0)

            self.is_active = False
            
            if self.monitor_id:
                try:
                    self.repository.record_monitoring_stop(self.monitor_id)
                except Exception as e:
                    logger.warning(f"Could not record monitoring stop in DB: {e}")

            return {"success": True, "message": "Monitoring service stopped successfully."}

    def get_status(self) -> Dict:
        """Return current status and metrics of the monitor."""
        return {
            "is_active": self.is_active,
            "monitor_id": self.monitor_id,
            "file_path": str(self.target_file_path) if self.target_file_path else None,
            "filename": self.target_file_path.name if self.target_file_path else None,
            "records_processed": self.records_processed,
            "errors_detected": self.errors_detected,
            "last_processed_timestamp": self.last_processed_timestamp.isoformat() if self.last_processed_timestamp else None,
            "active_error_groups_count": len(self.active_error_groups),
            "detected_incidents_count": len(self.detected_incidents),
            "last_error_message": self.last_error_message
        }

    def _monitor_loop(self, collector: FileTailCollector):
        """Worker loop reading appended lines periodically."""
        logger.info(f"Monitor loop started for {self.target_file_path}")
        
        while not self._stop_event.is_set():
            try:
                new_lines = list(collector.collect_new_lines())
                if new_lines:
                    self._process_batch(new_lines, collector.last_offset)
                time.sleep(1.0)  # Poll interval 1 sec
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                self.last_error_message = str(e)
                time.sleep(2.0)

        logger.info("Monitor loop stopped cleanly.")

    def _process_batch(self, new_lines: List[str], current_offset: int):
        """Process newly appended log lines."""
        if not new_lines:
            return

        records = self.parser.parse_text_lines(new_lines, source_file=self.target_file_path.name)
        if not records:
            return

        self.records_processed += len(records)
        self.last_processed_timestamp = datetime.utcnow()

        # Append to recent logs buffer
        for r in records:
            self.recent_logs.append(r)
            if r.severity in (SeverityLevel.ERROR, SeverityLevel.CRITICAL):
                self.errors_detected += 1

        # Group errors
        new_groups = self.grouper.group_records(records)
        for gid, eg in new_groups.items():
            if gid not in self.active_error_groups:
                self.active_error_groups[gid] = eg
            else:
                existing = self.active_error_groups[gid]
                existing.count += eg.count
                existing.last_seen = eg.last_seen or datetime.utcnow()
                existing.representative_records.extend(eg.representative_records)
                existing.representative_records = existing.representative_records[-5:]

        # Create/Update Incident Records for active error groups
        for gid, eg in self.active_error_groups.items():
            if eg.count >= 2:  # Threshold for active incident group
                incident_id = f"inc-{gid}"
                self.detected_incidents[incident_id] = Incident(
                    incident_id=incident_id,
                    title=f"{eg.severity.value} in {eg.service}: {eg.normalized_template[:60]}",
                    severity=eg.severity,
                    service=eg.service,
                    error_group_id=gid,
                    first_seen=eg.first_seen or datetime.utcnow(),
                    last_seen=eg.last_seen or datetime.utcnow(),
                    occurrence_count=eg.count,
                    status="OPEN",
                    representative_evidence=[r.message for r in eg.representative_records[:3]]
                )

        # Update checkpoint in database
        if self.monitor_id:
            try:
                self.repository.update_monitoring_checkpoint(
                    self.monitor_id,
                    current_offset,
                    self.records_processed,
                    self.errors_detected
                )
            except Exception as e:
                logger.debug(f"Failed to update monitoring checkpoint: {e}")

# Singleton instance accessor
monitoring_service = MonitoringService()
