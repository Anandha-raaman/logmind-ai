# LogMind AI — Real-Time Log Analysis & Root-Cause Assistant

LogMind AI is a Python-powered application log analytics, error grouping, anomaly detection, real-time tail monitoring, and GenAI root-cause investigation assistant.

## Features

- **Mode A — Log File Analysis:** Upload and process `.log`, `.txt`, and `.json` log files. Calculate severity breakdown, error rates, time-series distributions, and group recurring errors using deterministic fingerprinting.
- **Mode B — Real-Time Local Log Tail Monitoring:** Monitor local log file appends incrementally with byte offset tracking, handling partial lines, file rotation, and truncation without fake timers.
- **GenAI Incident Explanations:** Grounded incident analysis using Google Gemini SDK (`google-genai`). Generates Pydantic-validated structured reports with hypotheses, limitations, evidence, and investigation steps.
- **Security & Secret Redaction:** Automated redaction of API keys, passwords, bearer tokens, and connection strings before storage or external AI submission.
- **SQLite Persistence:** Atomic transaction persistence of analysis sessions, log records, error groups, incidents, and AI reports.
- **FastAPI REST API & Streamlit Dashboard:** Dual interface for programmatic API consumption and interactive web UI.

---

## Quick Start on Windows

### 1. Prerequisites & Virtual Environment Setup

```powershell
cd "f:\My projects\logmind-ai"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional for GenAI)

Copy `.env.example` to `.env` and set your Gemini API Key:

```powershell
cp .env.example .env
```

*(LogMind AI runs fully in local deterministic mode even without an API key).*

### 3. Run Automated Tests

```powershell
python -m pytest -q
```

### 4. Start FastAPI Backend

```powershell
python -m uvicorn api.main:app --reload --port 8000
```

FastAPI Interactive Swagger Docs available at: `http://127.0.0.1:8000/docs`

### 5. Start Streamlit Web UI

```powershell
streamlit run app.py
```

Streamlit Dashboard available at: `http://localhost:8501`

---

## Testing Real-Time Live Monitoring

1. Open Streamlit UI at `http://localhost:8501` -> **Live Monitor** tab.
2. Enter the path to `sample_logs/application.log`.
3. Click **Start Monitoring**.
4. In a terminal, append new log lines to `sample_logs/application.log`:

```powershell
Add-Content -Path "sample_logs/application.log" -Value "2026-10-02 15:00:00 [ERROR] [payment-service] New live tail test error event req_id=req-999"
```

5. Watch the Live Stream update dynamically!
