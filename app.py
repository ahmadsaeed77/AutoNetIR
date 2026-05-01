import csv
import io
import json
import os
import traceback
from datetime import datetime
from pathlib import Path

import streamlit as st

from core.runner import DETECTOR_REGISTRY, run_pipeline


st.set_page_config(
    page_title="AutoNetIR",
    layout="wide",
    page_icon="A",
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


def severity_color(severity):
    colors = {
        "HIGH": "#d92d20",
        "MEDIUM": "#b54708",
        "LOW": "#027a48",
        "UNKNOWN": "#475467",
    }
    return colors.get(str(severity).upper(), "#475467")


def severity_badge(severity):
    severity = str(severity or "UNKNOWN").upper()
    color = severity_color(severity)
    return (
        f"<span style='background:{color};color:white;padding:5px 10px;"
        f"border-radius:6px;font-size:12px;font-weight:700;'>{severity}</span>"
    )


def format_key(key):
    return key.replace("_", " ").title()


def render_value(key, value):
    if isinstance(value, list):
        if not value:
            st.write("No data")
            return

        if key == "ports" and len(value) > 40:
            st.write(f"{len(value)} ports observed. First 40 shown below.")
            st.write(", ".join(str(item) for item in value[:40]))
            with st.expander("Show full port list"):
                st.write(", ".join(str(item) for item in value))
            return

        st.write(", ".join(str(item) for item in value))
        return

    if isinstance(value, dict):
        if not value:
            st.write("No data")
            return

        for sub_key, sub_value in value.items():
            st.write(f"- **{format_key(str(sub_key))}:** {sub_value}")
        return

    st.write(value)


def render_alert_card(alert):
    alert_type = alert.get("alert_type", "Unknown Alert")
    severity = alert.get("severity", "UNKNOWN")
    evidence = alert.get("evidence", "No evidence available")
    recommendation = alert.get("recommendation", "No recommendation available")

    st.markdown(
        f"""
        <div style="
            border-left: 6px solid {severity_color(severity)};
            background-color: #101828;
            padding: 16px 18px;
            border-radius: 8px;
            margin-bottom: 10px;">
            <div style="display:flex;justify-content:space-between;gap:16px;align-items:flex-start;">
                <div>
                    <h3 style="margin:0;color:white;font-size:21px;">{alert_type}</h3>
                    <p style="margin:6px 0 0 0;color:#d0d5dd;">{evidence}</p>
                </div>
                <div>{severity_badge(severity)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("Alert evidence and response"):
        cols = st.columns(3)
        cols[0].metric("Confidence", alert.get("confidence", "UNKNOWN"))
        cols[1].metric("Source", alert.get("src_ip") or "N/A")
        cols[2].metric("Destination", alert.get("dst_ip") or "N/A")
        st.markdown("**Recommended response**")
        st.write(recommendation)
        st.markdown("**Attack category**")
        st.write(alert.get("mitre_or_attack_category", "N/A"))
        st.markdown("**Full alert fields**")
        for key, value in alert.items():
            if key in {"alert_type", "severity", "evidence", "recommendation"}:
                continue
            st.markdown(f"**{format_key(key)}**")
            render_value(key, value)


def render_summary(result, alerts):
    stats = result.get("stats", {})
    protocol_counts = stats.get("protocol_counts", {})
    high_alerts = sum(1 for alert in alerts if alert.get("severity") == "HIGH")
    medium_alerts = sum(1 for alert in alerts if alert.get("severity") == "MEDIUM")
    unique_sources = len({alert.get("src_ip") for alert in alerts if alert.get("src_ip")})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Parsed Packets", result.get("packet_count", 0))
    col2.metric("Total Alerts", len(alerts))
    col3.metric("High / Medium", f"{high_alerts} / {medium_alerts}")
    col4.metric("Alert Sources", unique_sources)

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("**Protocols Seen**")
        if protocol_counts:
            st.bar_chart(protocol_counts)
        else:
            st.caption("No protocol data")

    with col_b:
        st.markdown("**Top Source IPs**")
        for ip, count in stats.get("top_sources", [])[:6]:
            st.write(f"{ip}: {count}")

    with col_c:
        st.markdown("**Top Destination IPs**")
        for ip, count in stats.get("top_destinations", [])[:6]:
            st.write(f"{ip}: {count}")


def filter_alerts(alerts, severity, alert_type, source_ip, destination_ip):
    filtered = list(alerts)

    if severity != "ALL":
        filtered = [alert for alert in filtered if alert.get("severity", "UNKNOWN") == severity]

    if alert_type != "ALL":
        filtered = [alert for alert in filtered if alert.get("alert_type", "Unknown Alert") == alert_type]

    if source_ip != "ALL":
        filtered = [alert for alert in filtered if alert.get("src_ip") == source_ip]

    if destination_ip != "ALL":
        filtered = [alert for alert in filtered if alert.get("dst_ip") == destination_ip]

    return filtered


def alerts_to_csv(alerts):
    if not alerts:
        return ""

    fieldnames = sorted({key for alert in alerts for key in alert.keys()})
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()

    for alert in alerts:
        row = {}
        for key in fieldnames:
            value = alert.get(key, "")
            if isinstance(value, (list, dict)):
                row[key] = json.dumps(value, ensure_ascii=False)
            else:
                row[key] = value
        writer.writerow(row)

    return buffer.getvalue()


def save_uploaded_file(uploaded_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(
        char if char.isalnum() or char in "._-" else "_"
        for char in uploaded_file.name
    )
    save_path = UPLOAD_DIR / f"{timestamp}_{safe_name}"

    with open(save_path, "wb") as file:
        file.write(uploaded_file.getbuffer())

    return str(save_path)


def render_errors(errors):
    if not errors:
        return

    st.warning("The analysis completed with warnings or partial failures.")
    for error in errors:
        with st.expander(f"{error.get('stage', 'unknown').title()} issue"):
            st.write(error)


def render_project_explanation():
    st.subheader("Project Explanation")
    st.write(
        "AutoNetIR is a rule-based PCAP forensics assistant. It is designed to "
        "speed up the first triage step: parse captured traffic, detect common "
        "attack patterns, enrich public source IPs, and present evidence clearly."
    )

    st.markdown("**Architecture**")
    st.code(
        "Upload PCAP -> Normalize Events -> Run Detectors -> Enrich Alerts -> Visualize and Export",
        language="text",
    )

    st.markdown("**Supported Detection Rules**")
    for detector in DETECTOR_REGISTRY:
        status = "Enabled" if detector.get("enabled", True) else "Disabled"
        st.write(f"- **{detector['name']}** ({status}): {detector['description']}")

    st.markdown("**Report Talking Points**")
    st.write(
        "- Problem: manual PCAP investigation is slow and requires network security expertise.\n"
        "- Objective: automate initial triage and produce explainable incident-response alerts.\n"
        "- Method: threshold-based rules over normalized packet events.\n"
        "- Limitations: encrypted payloads, false positives from thresholds, TShark dependency, and VirusTotal rate limits.\n"
        "- Future work: live capture, SIEM export, more protocols, and anomaly scoring."
    )


def render_analysis_tab():
    with st.sidebar:
        st.markdown("## Analysis Control")
        uploaded_file = st.file_uploader("Upload PCAP / PCAPNG File", type=["pcap", "pcapng"])
        st.caption("AutoNetIR analyzes uploaded capture files and displays generated security alerts.")

    if uploaded_file is None:
        st.info("Upload a PCAP file from the sidebar to start analysis.")
        return

    st.success(f"Ready to analyze: {uploaded_file.name}")

    if st.button("Start Analysis", use_container_width=True):
        save_path = save_uploaded_file(uploaded_file)
        with st.spinner("Analyzing PCAP file..."):
            try:
                st.session_state["analysis_result"] = run_pipeline(save_path)
            except Exception:
                st.error("Analysis failed unexpectedly.")
                st.code(traceback.format_exc())
                return

    result = st.session_state.get("analysis_result")
    if not result:
        return

    if result.get("success"):
        st.success(f"Analysis completed. Run ID: {result.get('run_id')}")
    else:
        st.error("Parser failed. No alerts were generated.")

    render_errors(result.get("errors", []))

    all_alerts = result.get("alerts", [])
    render_summary(result, all_alerts)

    st.divider()
    st.subheader("Detected Alerts")

    alert_types = sorted({alert.get("alert_type", "Unknown Alert") for alert in all_alerts})
    source_ips = sorted({alert.get("src_ip") for alert in all_alerts if alert.get("src_ip")})
    destination_ips = sorted({alert.get("dst_ip") for alert in all_alerts if alert.get("dst_ip")})

    col1, col2, col3, col4 = st.columns(4)
    selected_severity = col1.selectbox("Severity", ["ALL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    selected_type = col2.selectbox("Alert Type", ["ALL"] + alert_types)
    selected_source = col3.selectbox("Source IP", ["ALL"] + source_ips)
    selected_destination = col4.selectbox("Destination IP", ["ALL"] + destination_ips)

    filtered_alerts = filter_alerts(
        all_alerts,
        selected_severity,
        selected_type,
        selected_source,
        selected_destination,
    )

    export_col1, export_col2, export_col3 = st.columns([1, 1, 3])
    export_col1.download_button(
        "Export JSON",
        data=json.dumps(filtered_alerts, indent=2, ensure_ascii=False),
        file_name=f"{result.get('run_id', 'autonetir')}_alerts.json",
        mime="application/json",
        use_container_width=True,
    )
    export_col2.download_button(
        "Export CSV",
        data=alerts_to_csv(filtered_alerts),
        file_name=f"{result.get('run_id', 'autonetir')}_alerts.csv",
        mime="text/csv",
        use_container_width=True,
    )
    export_col3.caption(f"Showing {len(filtered_alerts)} of {len(all_alerts)} alerts")

    if not filtered_alerts:
        st.info("No alerts match the selected filters.")
        return

    for alert in filtered_alerts:
        render_alert_card(alert)


st.markdown(
    """
    <div style="padding: 8px 0 18px 0;">
        <h1 style="font-size: 46px; margin-bottom: 0;">
            <span style="color:#0077b6;">Auto</span><span style="color:#0096c7;">Net</span><span style="color:#d92d20;">IR</span>
        </h1>
        <p style="font-size: 17px; color: #667085; margin-top: 4px;">
            Automated Network Forensics and Incident Response Dashboard
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

analysis_tab, explanation_tab = st.tabs(["Analysis Dashboard", "Project Explanation"])

with analysis_tab:
    render_analysis_tab()

with explanation_tab:
    render_project_explanation()
