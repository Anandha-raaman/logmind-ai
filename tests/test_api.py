import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "gemini_configured" in data


def test_api_upload_invalid_file_extension():
    response = client.post(
        "/api/v1/analyses",
        files={"file": ("test.exe", b"binary content", "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]


def test_api_upload_valid_log():
    log_content = b"2026-10-02 10:00:00 [ERROR] [user-service] Failed DB query req_id=req-1\n"
    response = client.post(
        "/api/v1/analyses",
        files={"file": ("test_api.log", log_content, "text/plain")}
    )
    assert response.status_code == 201
    data = response.json()
    assert "session_summary" in data
    assert data["session_summary"]["parsed_records"] == 1


def test_api_monitor_status():
    response = client.get("/api/v1/monitor/status")
    assert response.status_code == 200
    data = response.json()
    assert "is_active" in data
