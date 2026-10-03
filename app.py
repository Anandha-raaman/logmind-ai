import streamlit as st
from config.settings import settings
from database.db import init_db
from database.repository import LogMindRepository
from logmind.ai_analyzer import AIIncidentAnalyzer
from ui.components import apply_custom_theme
from ui.dashboard import render_dashboard
from ui.file_analysis import render_file_analysis
from ui.live_monitor import render_live_monitor
from ui.incident_details import render_incident_details
from ui.history import render_history
from ui.settings_page import render_settings_page

# Page Configuration
st.set_page_config(
    page_title="LogMind AI — Real-Time Log Analysis & Root-Cause Assistant",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Theme
apply_custom_theme()

# Initialize DB & Services
init_db()
repository = LogMindRepository()
ai_analyzer = AIIncidentAnalyzer()

# Sidebar Navigation
st.sidebar.title("⚡ LogMind AI")
st.sidebar.caption("Python-Powered Log Analytics & Root-Cause Engine")
st.sidebar.markdown("---")

navigation_selection = st.sidebar.radio(
    "Navigation",
    options=[
        "1. Overview",
        "2. File Analysis",
        "3. Live Monitor",
        "4. Incidents",
        "5. Analysis History",
        "6. Settings"
    ],
    index=0
)

st.sidebar.markdown("---")
if settings.is_gemini_configured:
    st.sidebar.success("🟢 GenAI: Active (Gemini)")
else:
    st.sidebar.info("🟡 GenAI: Offline / Unconfigured")

st.sidebar.caption("LogMind AI v1.0.0")

# Route to Page
if navigation_selection.startswith("1."):
    render_dashboard(repository)
elif navigation_selection.startswith("2."):
    render_file_analysis(repository, ai_analyzer)
elif navigation_selection.startswith("3."):
    render_live_monitor(repository)
elif navigation_selection.startswith("4."):
    render_incident_details(repository, ai_analyzer)
elif navigation_selection.startswith("5."):
    render_history(repository)
elif navigation_selection.startswith("6."):
    render_settings_page()
