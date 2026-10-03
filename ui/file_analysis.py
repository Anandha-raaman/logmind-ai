import os
import uuid
import pandas as pd
import streamlit as st
from pathlib import Path

from config.settings import settings
from database.repository import LogMindRepository
from logmind.ai_analyzer import AIIncidentAnalyzer
from logmind.analytics import AnalyticsEngine
from logmind.anomaly_detector import AnomalyDetector
from logmind.error_grouper import ErrorGrouper
from logmind.models import Incident, SeverityLevel
from logmind.parser import LogParser
from logmind.report_generator import ReportGenerator
from logmind.validators import validate_upload_content
from ui.components import render_metric_card, render_severity_badge, format_timestamp


def render_file_analysis(repository: LogMindRepository, ai_analyzer: AIIncidentAnalyzer):
    st.title("Log File Analysis Mode")
    st.caption("Upload and analyze `.log`, `.txt`, or `.json` files. Parse records, group errors, detect anomalies, and generate evidence-grounded reports.")

    uploaded_file = st.file_uploader(
        "Choose a log file to analyze",
        type=["log", "txt", "json"],
        help=f"Maximum file size: {settings.MAX_FILE_SIZE_MB} MB. Supports text logs & JSON logs."
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        is_valid, err_msg = validate_upload_content(uploaded_file.name, file_bytes)

        if not is_valid:
            st.error(f"File Validation Failed: {err_msg}")
            return

        # Check if already processed in session state
        if st.session_state.get("current_analyzed_file") != uploaded_file.name:
            with st.spinner(f"Parsing and analyzing {uploaded_file.name}..."):
                # Save temp file
                temp_dir = Path("data/uploads")
                temp_dir.mkdir(parents=True, exist_ok=True)
                session_id = f"sess-{str(uuid.uuid4())[:8]}"
                save_path = temp_dir / f"{session_id}_{uploaded_file.name}"

                with open(save_path, "wb") as f:
                    f.write(file_bytes)

                # Execute core pipeline
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
                    filename=uploaded_file.name,
                    file_size_bytes=len(file_bytes),
                    total_source_lines=stats.get("total_source_lines", stats.get("total", 0))
                )
                summary.anomalies_detected = len(anomalies)

                # Generate Incidents
                incidents = []
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

                # Save session to DB
                repository.save_analysis_session(summary, records, error_groups, incidents)

                if save_path.exists():
                    save_path.unlink()

                # Store in session state
                st.session_state["current_analyzed_file"] = uploaded_file.name
                st.session_state["current_summary"] = summary
                st.session_state["current_records"] = records
                st.session_state["current_error_groups"] = error_groups
                st.session_state["current_anomalies"] = anomalies
                st.session_state["current_incidents"] = incidents

        # Display Results
        summary = st.session_state["current_summary"]
        records = st.session_state["current_records"]
        error_groups = st.session_state["current_error_groups"]
        anomalies = st.session_state["current_anomalies"]
        incidents = st.session_state["current_incidents"]

        st.success(f"Analysis Complete: Processed {summary.total_records:,} log records from `{summary.filename}` ({summary.total_source_lines:,} source lines)")

        # Summary Metrics Row
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            render_metric_card("TOTAL RECORDS", f"{summary.total_records:,}", f"Source lines: {summary.total_source_lines:,}")
        with m2:
            render_metric_card("PARSED", f"{summary.parsed_records:,}")
        with m3:
            render_metric_card("MALFORMED", f"{summary.malformed_records:,}")
        with m4:
            render_metric_card("ERROR RATE", f"{summary.error_rate:.1f}%")
        with m5:
            render_metric_card("ERROR GROUPS", f"{len(error_groups):,}")

        st.markdown("---")

        # Tabs for detailed view
        tab_groups, tab_anomalies, tab_incidents, tab_malformed, tab_timeseries = st.tabs([
            "Error Groups", "Detected Anomalies", "Incident Investigation", "Malformed Records", "Time Series Trend"
        ])

        with tab_groups:
            st.subheader("Recurring Error Groups")
            if error_groups:
                group_data = []
                for gid, eg in error_groups.items():
                    group_data.append({
                        "Group ID": gid,
                        "Severity": eg.severity.value if hasattr(eg.severity, "value") else str(eg.severity),
                        "Service": eg.service,
                        "Occurrences": eg.count,
                        "Normalized Pattern": eg.normalized_template,
                        "First Seen": format_timestamp(eg.first_seen),
                        "Last Seen": format_timestamp(eg.last_seen)
                    })
                df_groups = pd.DataFrame(group_data).sort_values(by="Occurrences", ascending=False)
                st.dataframe(df_groups, use_container_width=True, hide_index=True)
            else:
                st.info("No recurring error groups detected.")

        with tab_anomalies:
            st.subheader("Statistical & Threshold Anomalies")
            if anomalies:
                for anom in anomalies:
                    st.warning(f"**[{anom.severity.value}] {anom.metric_name.upper()}**: {anom.explanation}")
            else:
                st.success("No anomalous error spikes or abnormal frequency distributions detected.")

        with tab_incidents:
            st.subheader("Incidents & AI Root Cause Explanations")
            if incidents:
                # Incident Summary Table
                inc_table_data = []
                for inc in incidents:
                    inc_table_data.append({
                        "incident_id": inc.incident_id,
                        "severity": inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
                        "service": inc.service,
                        "occurrence_count": inc.occurrence_count,
                        "message": inc.title,
                        "first_seen": format_timestamp(inc.first_seen),
                        "last_seen": format_timestamp(inc.last_seen)
                    })
                df_incidents = pd.DataFrame(inc_table_data)
                st.dataframe(df_incidents, use_container_width=True, hide_index=True)
                st.markdown("---")

                selected_inc = st.selectbox(
                    "Select an Incident to Investigate:",
                    incidents,
                    format_func=lambda x: f"[{x.severity.value}] {x.service}: {x.title[:60]} ({x.occurrence_count} events)"
                )

                if selected_inc:
                    st.markdown(f"### Incident: `{selected_inc.incident_id}` - {selected_inc.title}")
                    
                    # Representative evidence
                    st.markdown("**Representative Log Evidence:**")
                    for ev in selected_inc.representative_evidence:
                        st.code(ev, language="text")

                    # AI Explanation Action
                    if not selected_inc.ai_analysis:
                        if not settings.is_gemini_configured:
                            st.info("💡 Note: Gemini API key is not configured. Clicking 'Generate AI Analysis' will display deterministic evidence analysis.")
                        
                        if st.button("🤖 Generate AI Incident Explanation"):
                            with st.spinner("Analyzing log evidence with GenAI..."):
                                report = ai_analyzer.analyze_incident(selected_inc)
                                selected_inc.ai_analysis = report
                                repository.save_ai_analysis(selected_inc.incident_id, report)
                                st.rerun()
                    
                    # Render AI Analysis Report
                    if selected_inc.ai_analysis:
                        ai = selected_inc.ai_analysis
                        st.markdown("#### 🧠 AI Root-Cause Report")
                        st.markdown(f"**Summary:** {ai.incident_summary}")
                        
                        col_causes, col_steps = st.columns(2)
                        with col_causes:
                            st.markdown("**Hypothesized Root Causes:**")
                            for cause in ai.potential_root_causes:
                                st.markdown(f"- {cause}")
                        
                        with col_steps:
                            st.markdown("**Suggested Investigation Steps:**")
                            for step in ai.suggested_investigation_steps:
                                st.markdown(f"1. {step}")

                        st.caption(f"Confidence & Limitations: {ai.confidence_explanation}")

                        # Export controls
                        st.markdown("---")
                        col_ex1, col_ex2 = st.columns(2)
                        with col_ex1:
                            md_report = ReportGenerator.generate_incident_markdown_report(selected_inc, summary)
                            st.download_button(
                                "📥 Export Markdown Incident Report",
                                data=md_report,
                                file_name=f"logmind_incident_{selected_inc.incident_id}.md",
                                mime="text/markdown"
                            )
                        with col_ex2:
                            json_report = ReportGenerator.generate_incident_json_report(selected_inc)
                            st.download_button(
                                "📥 Export JSON Report",
                                data=json_report,
                                file_name=f"logmind_incident_{selected_inc.incident_id}.json",
                                mime="application/json"
                            )
            else:
                st.info("No critical incident threshold reached.")

        with tab_malformed:
            st.subheader("Malformed Records & Parsing Diagnostics")
            malformed_records = [r for r in records if r.parsing_status in ("MALFORMED", "PARTIAL")]
            if malformed_records:
                malformed_data = []
                for r in malformed_records:
                    malformed_data.append({
                        "Line #": r.line_number,
                        "Status": r.parsing_status.value if hasattr(r.parsing_status, 'value') else r.parsing_status,
                        "Parsing Reason": r.parsing_reason or "Unrecognized format",
                        "Raw Log Content": r.raw_content
                    })
                df_malformed = pd.DataFrame(malformed_data)
                st.dataframe(df_malformed, use_container_width=True, hide_index=True)
            else:
                st.success("No malformed records or parsing errors found in this log file.")

        with tab_timeseries:
            st.subheader("Time-Series Error Volume")
            ts_data = AnalyticsEngine.get_time_series_data(records)
            if ts_data:
                df_ts = pd.DataFrame(ts_data)
                df_ts["timestamp"] = pd.to_datetime(df_ts["timestamp"])
                df_chart = df_ts.set_index("timestamp")[["error_count", "warning_count", "total_records"]]
                st.line_chart(df_chart)
            else:
                st.info("Timestamps unavailable in raw records for time-series aggregation.")
