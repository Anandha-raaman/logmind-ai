import json
from datetime import datetime
from typing import Dict, List, Optional
from logmind.models import AIAnalysisReport, AnalysisSessionSummary, Incident, LogRecord


class ReportGenerator:
    """Generates markdown and JSON incident export reports."""

    @staticmethod
    def generate_incident_markdown_report(incident: Incident, summary: Optional[AnalysisSessionSummary] = None) -> str:
        ai = incident.ai_analysis
        
        md = []
        md.append(f"# 🚨 LogMind AI Incident Report: {incident.title}")
        md.append(f"**Generated At:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        md.append("")
        md.append("## 📌 Incident Summary")
        md.append(f"- **Incident ID:** `{incident.incident_id}`")
        md.append(f"- **Service:** `{incident.service}`")
        md.append(f"- **Severity:** `{incident.severity.value}`")
        md.append(f"- **Occurrences:** `{incident.occurrence_count}`")
        md.append(f"- **First Seen:** `{incident.first_seen}`")
        md.append(f"- **Last Seen:** `{incident.last_seen}`")
        md.append(f"- **Status:** `{incident.status}`")
        md.append("")

        md.append("## 🔍 Representative Log Evidence")
        if incident.representative_evidence:
            md.append("```text")
            for ev in incident.representative_evidence:
                md.append(ev)
            md.append("```")
        else:
            md.append("_No representative evidence captured._")
        md.append("")

        if ai:
            md.append("## 🤖 GenAI Incident Analysis & Root Causes")
            md.append(f"**Overview:** {ai.incident_summary}")
            md.append("")
            
            md.append("### 🎯 Hypothesized Root Causes")
            for cause in ai.potential_root_causes:
                md.append(f"- {cause}")
            md.append("")

            md.append("### 📊 Supporting Evidence")
            for ev in ai.supporting_evidence:
                md.append(f"- `{ev}`")
            md.append("")

            md.append("### 🛠️ Recommended Investigation Steps")
            for step in ai.suggested_investigation_steps:
                md.append(f"1. {step}")
            md.append("")

            md.append("### ⚠️ Evidence Limitations & Uncertainties")
            for lim in ai.evidence_limitations:
                md.append(f"- {lim}")
            md.append("")

            md.append(f"**Impact:** {ai.potential_impact}")
            md.append(f"**Confidence:** {ai.confidence_explanation}")
        
        return "\n".join(md)

    @staticmethod
    def generate_incident_json_report(incident: Incident) -> str:
        return json.dumps(incident.model_dump(mode="json"), indent=2)
