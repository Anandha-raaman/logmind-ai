import streamlit as st
from typing import Dict, List, Optional
from logmind.models import SeverityLevel


def apply_custom_theme():
    """Apply modern technical developer styling to Streamlit."""
    st.markdown(
        """
        <style>
        /* Base page font & layout */
        .main {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
        }
        
        /* Metric Card styling */
        .metric-card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            text-align: left;
            margin-bottom: 12px;
        }
        .metric-card .metric-label {
            font-size: 0.825rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        .metric-card .metric-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: #f0f6fc;
            margin-top: 4px;
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 12px;
            text-transform: uppercase;
        }
        .badge-critical { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }
        .badge-error { background-color: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; }
        .badge-warning { background-color: #78350f; color: #fde68a; border: 1px solid #92400e; }
        .badge-info { background-color: #1e3a8a; color: #93c5fd; border: 1px solid #1e40af; }
        .badge-debug { background-color: #374151; color: #d1d5db; border: 1px solid #4b5563; }
        
        /* Log evidence snippet */
        .log-snippet {
            background-color: #0d1117;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 10px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 0.85rem;
            color: #e6edf3;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        /* Status Banner */
        .status-banner {
            padding: 10px 16px;
            border-radius: 6px;
            font-weight: 500;
            font-size: 0.9rem;
            margin-bottom: 16px;
        }
        .status-banner-active { background-color: #064e3b; color: #6ee7b7; border: 1px solid #047857; }
        .status-banner-idle { background-color: #1f2937; color: #9ca3af; border: 1px solid #374151; }
        </style>
        """,
        unsafe_allow_html=True
    )


def render_metric_card(label: str, value: str, subtext: Optional[str] = None):
    sub_html = f"<div style='font-size:0.75rem; color:#8b949e; margin-top:2px;'>{subtext}</div>" if subtext else ""
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            {sub_html}
        </div>
        """,
        unsafe_allow_html=True
    )


def render_severity_badge(severity: SeverityLevel) -> str:
    sev_str = severity.value.lower()
    if sev_str in ("critical", "error"):
        css_cls = "badge-error"
    elif sev_str == "warning":
        css_cls = "badge-warning"
    elif sev_str == "info":
        css_cls = "badge-info"
    else:
        css_cls = "badge-debug"
    return f"<span class='badge {css_cls}'>{severity.value}</span>"


def format_timestamp(ts) -> str:
    """Safely format datetime, string timestamp, or None for clean UI table rendering without orphan rows."""
    if ts is None:
        return "N/A"
    if hasattr(ts, "strftime"):
        return ts.strftime("%H:%M:%S")
    ts_str = str(ts).strip()
    if not ts_str or ts_str.upper() in ("NONE", "N/A", "NULL"):
        return "N/A"
    if "T" in ts_str:
        return ts_str.split("T")[-1][:8]
    if " " in ts_str:
        parts = ts_str.split(" ")
        if len(parts) > 1 and ":" in parts[1]:
            return parts[1][:8]
    return ts_str[:8]

