import streamlit as st
from database.repository import LogMindRepository
from logmind.ai_analyzer import AIIncidentAnalyzer
from logmind.report_generator import ReportGenerator
from ui.components import render_severity_badge


def render_incident_details(repository: LogMindRepository, ai_analyzer: AIIncidentAnalyzer):
    st.title("Incident Details & AI Investigations")
    st.caption("Deep-dive into specific error incidents, inspect representative log evidence, and analyze AI hypotheses.")

    incidents = repository.get_incidents_for_session()

    if not incidents:
        st.info("No recorded incidents available in the database. Perform a file analysis or start live monitoring to generate incident reports.")
        return

    selected_incident = st.selectbox(
        "Select Incident to Inspect:",
        incidents,
        format_func=lambda i: f"[{i.severity.value}] {i.service}: {i.title[:60]} ({i.occurrence_count} events)"
    )

    if selected_incident:
        st.markdown("---")
        badge = render_severity_badge(selected_incident.severity)
        st.markdown(f"## {selected_incident.title} {badge}", unsafe_allow_html=True)
        
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Incident ID", selected_incident.incident_id)
        with c2:
            st.metric("Service Name", selected_incident.service)
        with c3:
            st.metric("Occurrence Count", selected_incident.occurrence_count)
        with c4:
            st.metric("Status", selected_incident.status)

        st.markdown("### 📜 Log Evidence Snippets")
        for ev in selected_incident.representative_evidence:
            st.code(ev, language="text")

        st.markdown("---")
        st.markdown("### 🤖 GenAI Incident Analysis Report")

        if not selected_incident.ai_analysis:
            if st.button("⚡ Run AI Analysis Now"):
                with st.spinner("Generating AI Analysis report..."):
                    report = ai_analyzer.analyze_incident(selected_incident)
                    repository.save_ai_analysis(selected_incident.incident_id, report)
                    selected_incident.ai_analysis = report
                    st.rerun()
        else:
            ai = selected_incident.ai_analysis
            st.markdown(f"**Summary:** {ai.incident_summary}")
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Hypothesized Root Causes:**")
                for c in ai.potential_root_causes:
                    st.markdown(f"- {c}")

                st.markdown("**Supporting Evidence:**")
                for e in ai.supporting_evidence:
                    st.markdown(f"- `{e}`")

            with col_b:
                st.markdown("**Suggested Investigation Steps:**")
                for s in ai.suggested_investigation_steps:
                    st.markdown(f"1. {s}")

                st.markdown("**Evidence Limitations:**")
                for l in ai.evidence_limitations:
                    st.markdown(f"- {l}")

            st.info(f"**Potential Impact:** {ai.potential_impact}\n\n**Confidence Explanation:** {ai.confidence_explanation}")

            # Export Buttons
            st.markdown("---")
            md_content = ReportGenerator.generate_incident_markdown_report(selected_incident)
            st.download_button(
                "📥 Download Markdown Report",
                data=md_content,
                file_name=f"incident_{selected_incident.incident_id}.md",
                mime="text/markdown"
            )
