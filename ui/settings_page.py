import streamlit as st
from config.settings import settings


def render_settings_page():
    st.title("Application Settings & Configuration")
    st.caption("Inspect system limits, security redaction parameters, and GenAI provider connection status.")

    st.markdown("### 🔑 GenAI Provider Status")
    
    col_gem1, col_gem2 = st.columns(2)
    with col_gem1:
        if settings.is_gemini_configured:
            st.success("🟢 Gemini API Status: Configured")
            st.caption("SDK: `google-genai` | Model: `gemini-2.5-flash`")
        else:
            st.warning("🟡 Gemini API Status: Not Configured")
            st.caption("Set `GEMINI_API_KEY` in `.env` or environment variables to enable GenAI incident explanations.")

    with col_gem2:
        st.info("🔒 Security Protection: API Keys are read securely from environment variables or `.env` and are NEVER rendered in text fields, API responses, or exported reports.")

    st.markdown("---")

    st.markdown("### 🛡️ Security & Secret Redaction Settings")
    st.checkbox("Enable Automatic Secret Redaction", value=settings.SECRET_REDACTION_ENABLED, disabled=True)
    st.caption("Redacts API keys, Bearer tokens, passwords, connection strings, and AWS credentials before storage or AI submission.")

    st.markdown("---")

    st.markdown("### 📈 Anomaly Detection Thresholds")
    col_t1, col_t2, col_t3 = st.columns(3)
    with col_t1:
        st.number_input("Spike Threshold (Std Devs)", value=settings.DEFAULT_SPIKE_THRESHOLD_STD, disabled=True)
    with col_t2:
        st.number_input("Min Events for Anomaly", value=settings.DEFAULT_MIN_EVENTS_FOR_ANOMALY, disabled=True)
    with col_t3:
        st.number_input("Window Interval (Minutes)", value=settings.DEFAULT_WINDOW_MINUTES, disabled=True)

    st.markdown("---")

    st.markdown("### 🗄️ Database & Environment Information")
    st.text(f"Environment: {settings.ENVIRONMENT}")
    st.text(f"SQLite DB Path: {settings.DB_PATH}")
    st.text(f"Max Upload Limit: {settings.MAX_FILE_SIZE_MB} MB")
