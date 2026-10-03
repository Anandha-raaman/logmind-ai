import os
import time
import pandas as pd
import streamlit as st
from pathlib import Path

from config.settings import settings
from database.repository import LogMindRepository
from logmind.monitoring_service import monitoring_service
from ui.components import render_metric_card, render_severity_badge


def render_live_monitor(repository: LogMindRepository):
    st.title("Real-Time Local Log File Monitor")
    st.caption("Monitor an authorized local log file in real time as new lines are appended. Uses incremental offset tailing.")

    status = monitoring_service.get_status()
    is_active = status["is_active"]

    # 1. Configuration & Controls Box
    st.markdown("### ⚙️ Monitoring Controls")

    col_file, col_btn = st.columns([3, 1])

    with col_file:
        default_file = str(Path("sample_logs/application.log").resolve())
        target_path = st.text_input(
            "Authorized Local Test Log File Path:",
            value=status["file_path"] if status["file_path"] else default_file,
            disabled=is_active,
            help="Path to an authorized local test log file. File must exist."
        )

    with col_btn:
        st.write(" ")
        st.write(" ")
        if not is_active:
            if st.button("▶️ Start Monitoring", type="primary"):
                if not Path(target_path).exists():
                    st.error(f"Target file does not exist: {target_path}")
                else:
                    res = monitoring_service.start_monitoring(target_path, tail_from_end=False)
                    if res["success"]:
                        st.success(res["message"])
                        st.rerun()
                    else:
                        st.error(res["message"])
        else:
            if st.button("⏹️ Stop Monitoring"):
                res = monitoring_service.stop_monitoring()
                if res["success"]:
                    st.info(res["message"])
                    st.rerun()
                else:
                    st.error(res["message"])

    st.markdown("---")

    # 2. Status & Live Metrics
    st.markdown("### 📊 Live Monitoring Dashboard")
    
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        mon_str = "🟢 RUNNING" if is_active else "⚪ STOPPED"
        render_metric_card("MONITOR STATE", mon_str, status["monitor_id"] or "Inactive")

    with col2:
        render_metric_card("RECORDS PROCESSED", f"{status['records_processed']:,}")

    with col3:
        render_metric_card("ERRORS DETECTED", f"{status['errors_detected']:,}")

    with col4:
        last_ts = status["last_processed_timestamp"] or "N/A"
        render_metric_card("LAST TAIL TIME", last_ts.split("T")[-1][:8] if "T" in last_ts else last_ts)

    if status["last_error_message"]:
        st.error(f"Monitor Warning/Error: {status['last_error_message']}")

    st.markdown("---")

    # 3. Live Stream Table & Active Incidents
    col_stream, col_incidents = st.columns([2, 1])

    with col_stream:
        st.subheader("📡 Live Log Stream (Recent 50 Records)")
        logs = list(monitoring_service.recent_logs)
        if logs:
            log_data = []
            for r in reversed(logs[-50:]):
                log_data.append({
                    "Timestamp": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "N/A",
                    "Severity": r.severity.value,
                    "Service": r.service,
                    "Message": r.message[:100]
                })
            df_logs = pd.DataFrame(log_data)
            st.dataframe(df_logs, use_container_width=True, hide_index=True)
        else:
            st.info("No log events captured yet. Append lines to the target file to see live tail output.")

    with col_incidents:
        st.subheader("🚨 Live Detected Incidents")
        incidents = list(monitoring_service.detected_incidents.values())
        if incidents:
            for inc in incidents:
                with st.container():
                    st.markdown(f"**{inc.title[:50]}**")
                    st.caption(f"Service: `{inc.service}` | Count: `{inc.occurrence_count}`")
                    st.markdown("---")
        else:
            st.info("No error incidents detected during current live tail session.")

    # 4. Auto Refresh Notice / Manual Trigger
    if is_active:
        st.caption("🔄 Real-time tailing active in background thread. Click below to refresh metrics dashboard.")
        if st.button("↻ Refresh Live Metrics"):
            st.rerun()
