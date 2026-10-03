import time
import pytest
from pathlib import Path
from logmind.log_collector import FileTailCollector
from logmind.monitoring_service import MonitoringService


def test_file_tail_collector_reads_appended_lines(tmp_path):
    log_file = tmp_path / "live_test.log"
    log_file.write_text("Line 1\nLine 2\n", encoding="utf-8")

    collector = FileTailCollector(log_file)
    collector.seek_to_beginning()

    lines = list(collector.collect_new_lines())
    assert len(lines) == 2
    assert lines[0] == "Line 1"
    assert lines[1] == "Line 2"

    # Append Line 3
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("Line 3\n")

    new_lines = list(collector.collect_new_lines())
    assert len(new_lines) == 1
    assert new_lines[0] == "Line 3"


def test_monitoring_service_lifecycle(tmp_path):
    log_file = tmp_path / "mon_service.log"
    log_file.write_text("2026-10-02 10:00:00 [ERROR] [svc] initial error\n", encoding="utf-8")

    service = MonitoringService()
    start_res = service.start_monitoring(str(log_file), tail_from_end=False)
    assert start_res["success"] is True

    # Repeated start should fail safely
    repeat_res = service.start_monitoring(str(log_file))
    assert repeat_res["success"] is False

    time.sleep(1.2)  # Give worker thread time to process 1 cycle
    status = service.get_status()
    assert status["is_active"] is True
    assert status["records_processed"] >= 1

    stop_res = service.stop_monitoring()
    assert stop_res["success"] is True
    assert service.get_status()["is_active"] is False
