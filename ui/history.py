import pandas as pd
import streamlit as st
from database.repository import LogMindRepository
from ui.components import format_timestamp


def render_history(repository: LogMindRepository):
    st.title("Analysis History")
    st.caption("View and inspect past log analysis sessions stored in SQLite persistent database.")

    sessions = repository.get_analysis_sessions(limit=100)

    if not sessions:
        st.info("No historical analysis sessions found in the database.")
        return

    df_sess = pd.DataFrame(sessions)
    df_sess["created_at"] = pd.to_datetime(df_sess["created_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")

    st.markdown(f"**Total Past Sessions:** `{len(sessions)}`")

    st.dataframe(
        df_sess[[
            "session_id", "filename", "file_size_bytes", "total_records",
            "parsed_records", "malformed_records", "error_rate", "created_at"
        ]],
        use_container_width=True,
        hide_index=True
    )

    st.markdown("---")
    selected_session_id = st.selectbox(
        "Select Session ID to load incidents:",
        [s["session_id"] for s in sessions]
    )

    if selected_session_id:
        incidents = repository.get_incidents_for_session(selected_session_id)
        st.subheader(f"Incidents for Session `{selected_session_id}` ({len(incidents)})")
        if incidents:
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
            st.dataframe(pd.DataFrame(inc_table_data), use_container_width=True, hide_index=True)

            for inc in incidents:
                with st.expander(f"[{inc.severity.value}] {inc.service}: {inc.title}"):
                    st.write(f"**Occurrences:** {inc.occurrence_count}")
                    st.write(f"**First Seen:** {format_timestamp(inc.first_seen)}")
                    st.write(f"**Last Seen:** {format_timestamp(inc.last_seen)}")
                    st.markdown("**Representative Log Evidence:**")
                    for ev in inc.representative_evidence:
                        st.code(ev, language="text")
        else:
            st.info("No critical incidents recorded in this session.")

