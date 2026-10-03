import streamlit as st
import pandas as pd
from typing import Dict
from database.repository import LogMindRepository
from logmind.monitoring_service import monitoring_service
from ui.components import render_metric_card, render_severity_badge


def render_dashboard(repository: LogMindRepository):
    st.title("System Overview")
    st.caption("Real-time monitoring metrics, active error groups, and historical analytics summary.")

    # 1. Top Bar Status Cards
    status = monitoring_service.get_status()
    is_active = status["is_active"]

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        mon_str = "ACTIVE (LIVE)" if is_active else "IDLE (STOPPED)"
        mon_sub = f"File: {status['filename']}" if is_active and status['filename'] else "No active tail"
        render_metric_card("MONITOR STATUS", mon_str, mon_sub)

    with col2:
        sessions = repository.get_analysis_sessions(limit=100)
        total_records_processed = sum(s["total_records"] for s in sessions) + status["records_processed"]
        render_metric_card("TOTAL RECORDS", f"{total_records_processed:,}", f"Across {len(sessions)} session(s)")

    with col3:
        incidents = repository.get_incidents_for_session()
        active_incidents = [i for i in incidents if i.status == "OPEN"]
        render_metric_card("ACTIVE INCIDENTS", str(len(active_incidents)), f"Total recorded: {len(incidents)}")

    with col4:
        avg_error_rate = (sum(s["error_rate"] for s in sessions) / len(sessions)) if sessions else 0.0
        render_metric_card("AVG ERROR RATE", f"{avg_error_rate:.1f}%", "Historical baseline")

    st.markdown("---")

    # 2. Main Content Split
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("Recent Analysis Sessions")
        if sessions:
            df_sess = pd.DataFrame(sessions)
            df_sess["created_at"] = pd.to_datetime(df_sess["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            df_display = df_sess[["session_id", "filename", "total_records", "parsed_records", "error_rate", "created_at"]]
            df_display.columns = ["Session ID", "Filename", "Total", "Parsed", "Error Rate (%)", "Created At"]
            st.dataframe(df_display, use_container_width=True, hide_index=True)
        else:
            st.info("No log analysis sessions recorded yet. Upload a log file in the 'File Analysis' section to get started.")

    with col_right:
        st.subheader("Active Incidents Overview")
        if incidents:
            for inc in incidents[:5]:
                with st.container():
                    badge = render_severity_badge(inc.severity)
                    st.markdown(f"**{inc.title[:50]}...** {badge}", unsafe_allow_html=True)
                    st.caption(f"Service: `{inc.service}` | Occurrences: `{inc.occurrence_count}` | Status: `{inc.status}`")
                    st.markdown("---")
        else:
            st.success("No active critical incidents detected.")
