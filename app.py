import csv
import html
import io
import json
import os
import time
import traceback
from collections import Counter
from datetime import datetime
from pathlib import Path

import streamlit as st

from core.runner import run_pipeline
from detection.hybrid.registry import ATTACK_REGISTRY
from detection.time_windows import event_timestamp
from parser.pcap_parser import get_tshark_path


st.set_page_config(
    page_title="AutoNetIR PCAP Analysis",
    layout="wide",
    page_icon="A",
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

PIPELINE_STAGES = [
    "Upload",
    "Parse",
    "Extract Events",
    "Signature Detection",
    "Behavior Detection",
    "Hybrid Correlation",
    "Enrichment",
    "Results",
]


def inject_css():
    st.markdown(
        """
        <style>
        html, body, [data-testid="stAppViewContainer"] {
            background: #07111f;
            color: #e5eef8;
        }
        .block-container {
            max-width: 1460px;
            padding-top: 1rem;
            padding-bottom: 2rem;
        }
        [data-testid="stSidebar"] {
            background: #050b14;
            border-right: 1px solid #163047;
        }
        [data-testid="stSidebar"] * {
            color: #e5eef8;
        }
        [data-testid="stSidebar"] .stButton > button {
            background: #00a3a3;
            color: #04111f;
            border: 0;
            border-radius: 8px;
            font-weight: 850;
            min-height: 42px;
        }
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
            color: #9fb3c8;
        }
        .hero {
            background: linear-gradient(135deg, #0b1b2b 0%, #102f45 55%, #0b1b2b 100%);
            border: 1px solid #1e4662;
            border-radius: 8px;
            padding: 18px 20px;
            margin-bottom: 14px;
            box-shadow: 0 14px 32px rgba(0, 0, 0, 0.28);
        }
        .hero-row {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 18px;
        }
        .brand {
            color: #f8fbff;
            font-size: 30px;
            font-weight: 900;
            letter-spacing: 0;
            margin: 0;
        }
        .subtitle {
            color: #b8cadb;
            font-size: 14px;
            margin: 5px 0 0 0;
        }
        .status-row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            justify-content: flex-end;
        }
        .pill, .status-pill, .badge {
            display: inline-flex;
            align-items: center;
            border-radius: 8px;
            padding: 7px 10px;
            font-size: 12px;
            font-weight: 850;
            white-space: nowrap;
        }
        .pill {
            color: #d9e8f7;
            background: rgba(255, 255, 255, 0.07);
            border: 1px solid rgba(255, 255, 255, 0.12);
        }
        .status-pill, .badge {
            color: white;
        }
        .panel, .card, .alert-card, .upload-card, .drawer {
            background: #0d1b2a;
            border: 1px solid #203a52;
            border-radius: 8px;
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.2);
        }
        .panel {
            padding: 15px 17px;
            margin-bottom: 12px;
        }
        .upload-card {
            padding: 22px;
            margin-bottom: 14px;
        }
        .panel-title {
            color: #f8fbff;
            font-size: 17px;
            font-weight: 900;
            margin: 0 0 7px 0;
        }
        .panel-copy {
            color: #9fb3c8;
            font-size: 13px;
            margin: 0;
        }
        .kpi {
            background: #0d1b2a;
            border: 1px solid #203a52;
            border-radius: 8px;
            padding: 15px 16px;
            min-height: 105px;
        }
        .kpi-label {
            color: #9fb3c8;
            font-size: 12px;
            font-weight: 850;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .kpi-value {
            color: #f8fbff;
            font-size: 26px;
            font-weight: 900;
            line-height: 1.08;
            overflow-wrap: anywhere;
        }
        .kpi-note {
            color: #8ca6bd;
            font-size: 12px;
            margin-top: 6px;
        }
        .stage-wrap {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .stage {
            border-radius: 8px;
            border: 1px solid #203a52;
            padding: 8px 10px;
            background: #091525;
            color: #d9e8f7;
            font-size: 12px;
            font-weight: 850;
        }
        .stage small {
            color: #9fb3c8;
            font-weight: 800;
            margin-left: 6px;
        }
        .alert-card {
            padding: 14px 15px;
            margin-bottom: 10px;
        }
        .alert-head {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 8px;
        }
        .alert-title {
            color: #f8fbff;
            font-size: 17px;
            font-weight: 900;
            margin: 0;
        }
        .flow {
            color: #b8cadb;
            font-size: 13px;
            font-weight: 800;
            margin-top: 4px;
        }
        .evidence {
            color: #d9e8f7;
            font-size: 14px;
            margin: 8px 0 0 0;
        }
        .mini-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 8px;
            margin-top: 10px;
        }
        .mini {
            background: #091525;
            border: 1px solid #203a52;
            border-radius: 8px;
            padding: 8px 10px;
        }
        .mini-label {
            color: #9fb3c8;
            font-size: 11px;
            font-weight: 850;
            text-transform: uppercase;
        }
        .mini-value {
            color: #f8fbff;
            font-size: 13px;
            font-weight: 850;
            margin-top: 2px;
            overflow-wrap: anywhere;
        }
        .drawer {
            padding: 15px 16px;
            position: sticky;
            top: 12px;
        }
        .drawer-block {
            background: #091525;
            border: 1px solid #203a52;
            border-radius: 8px;
            padding: 11px 12px;
            margin-bottom: 10px;
        }
        .drawer-title {
            color: #7dd3fc;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            margin-bottom: 7px;
        }
        .drawer-copy {
            color: #d9e8f7;
            font-size: 13px;
            margin: 0;
        }
        .coverage-card {
            background: #0d1b2a;
            border: 1px solid #203a52;
            border-radius: 8px;
            padding: 13px 15px;
            margin-bottom: 10px;
        }
        .coverage-title {
            color: #f8fbff;
            font-weight: 900;
            margin-bottom: 5px;
        }
        .coverage-copy {
            color: #b8cadb;
            font-size: 13px;
            margin: 0;
        }
        @media (max-width: 950px) {
            .hero-row, .alert-head {
                display: block;
            }
            .status-row {
                justify-content: flex-start;
                margin-top: 12px;
            }
            .mini-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def safe_text(value):
    if value is None or value == "":
        return "N/A"
    return html.escape(str(value))


def format_number(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value or 0)


def format_bytes(value):
    if value is None:
        return "N/A"
    size = float(value)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_duration(seconds):
    if seconds is None:
        return "N/A"
    if seconds < 1:
        return f"{seconds:.3f}s"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    remaining = seconds % 60
    return f"{minutes}m {remaining:.1f}s"


def format_time(value):
    if value is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(value)


def severity_color(severity):
    return {
        "HIGH": "#ef4444",
        "MEDIUM": "#f59e0b",
        "LOW": "#22c55e",
    }.get(str(severity).upper(), "#64748b")


def method_color(method):
    return {
        "hybrid": "#8b5cf6",
        "signature": "#06b6d4",
        "behavior": "#f97316",
    }.get(str(method).lower(), "#64748b")


def status_color(status):
    return {
        "Completed": "#22c55e",
        "Running": "#06b6d4",
        "Failed": "#ef4444",
        "Pending": "#64748b",
    }.get(status, "#64748b")


def badge(text, color):
    return f"<span class='badge' style='background:{color};'>{safe_text(text)}</span>"


def status_badge(text):
    return f"<span class='status-pill' style='background:{status_color(text)};'>{safe_text(text)}</span>"


def format_key(key):
    return str(key).replace("_", " ").title()


def attack_label(attack_type):
    labels = {attack["id"]: attack["name"] for attack in ATTACK_REGISTRY}
    labels.update({
        "dos_attack": "DoS",
        "port_scan": "Port Scan",
        "arp_poisoning": "ARP Poisoning",
        "ssh_bruteforce": "SSH Brute Force",
        "http_login_bruteforce": "HTTP Login Brute Force",
    })
    return labels.get(attack_type, format_key(attack_type))


def save_uploaded_file(uploaded_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in uploaded_file.name)
    save_path = UPLOAD_DIR / f"{timestamp}_{safe_name}"
    with open(save_path, "wb") as file:
        file.write(uploaded_file.getbuffer())
    return str(save_path)


def environment_status():
    try:
        tshark_path = get_tshark_path()
        tshark = f"TShark ready: {Path(tshark_path).name}"
    except Exception:
        tshark = "TShark not found"
    vt = "VirusTotal enabled" if os.getenv("VT_API_KEY") else "VirusTotal key not set"
    return tshark, vt


def read_jsonl(path):
    if not path or not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def derive_capture_metadata(result):
    events_path = result.get("events_path") if result else None
    first_ts = None
    last_ts = None
    event_count = 0

    for event in read_jsonl(events_path) or []:
        event_count += 1
        timestamp = event_timestamp(event)
        if timestamp is None:
            continue
        first_ts = timestamp if first_ts is None else min(first_ts, timestamp)
        last_ts = timestamp if last_ts is None else max(last_ts, timestamp)

    duration = None
    if first_ts is not None and last_ts is not None:
        duration = max(0, last_ts - first_ts)

    return {
        "first_packet_time": first_ts,
        "last_packet_time": last_ts,
        "capture_duration": duration,
        "event_count": event_count or result.get("packet_count", 0) if result else 0,
    }


def run_analysis(uploaded_file):
    st.session_state["analysis_status"] = "Running"
    st.session_state["pcap_file_name"] = uploaded_file.name
    st.session_state["pcap_file_size"] = uploaded_file.size
    save_path = save_uploaded_file(uploaded_file)

    start = time.perf_counter()
    with st.spinner("Analyzing uploaded PCAP..."):
        try:
            result = run_pipeline(save_path)
        except Exception:
            result = {
                "success": False,
                "alerts": [],
                "errors": [{
                    "stage": "application",
                    "message": "Analysis failed unexpectedly.",
                    "details": traceback.format_exc(),
                }],
            }

    st.session_state["processing_time"] = time.perf_counter() - start
    st.session_state["analysis_result"] = result
    st.session_state["capture_metadata"] = derive_capture_metadata(result)
    st.session_state["analysis_status"] = "Completed" if result.get("success") else "Failed"


def render_upload_card(after_analysis=False):
    title = "Analyze Another PCAP" if after_analysis else "Drag & Drop PCAP"
    copy = "Upload a new capture to replace the current analysis run." if after_analysis else "Browse or drop a .pcap/.pcapng file, then start the forensic analysis."

    st.markdown(
        f"""
        <div class="upload-card">
            <p class="panel-title">{safe_text(title)}</p>
            <p class="panel-copy">{safe_text(copy)}</p>
            <p class="panel-copy">Supported formats: .pcap, .pcapng</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    uploaded_file = st.file_uploader("Browse File", type=["pcap", "pcapng"], key="pcap_upload")
    if st.button("Start Analysis", use_container_width=True, disabled=uploaded_file is None):
        run_analysis(uploaded_file)
        st.rerun()


def render_waiting_panel():
    st.markdown(
        """
        <div class="panel">
            <p class="panel-title">No PCAP Analysis Yet</p>
            <p class="panel-copy">Upload a PCAP from the analysis card above to populate this section.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar():
    tshark, vt = environment_status()
    with st.sidebar:
        st.markdown("## AutoNetIR")
        st.caption("Forensic PCAP Analysis Dashboard")
        st.markdown("### Detection Mode")
        st.markdown("- Hybrid IDS")
        st.markdown("- Signature + Behavior")
        st.markdown("- Time-window evidence")
        st.markdown("### Supported Attacks")
        for attack in ATTACK_REGISTRY:
            st.markdown(f"- {attack_label(attack['id'])}")
        st.markdown("### Environment")
        st.caption(tshark)
        st.caption(vt)


def current_status(result):
    if st.session_state.get("analysis_status") == "Running":
        return "Running"
    if result and result.get("success"):
        return "Completed"
    if result and not result.get("success"):
        return "Failed"
    return "Pending"


def render_header(result):
    metadata = st.session_state.get("capture_metadata", {})
    status = current_status(result)
    file_name = st.session_state.get("pcap_file_name", "No PCAP analyzed")
    file_size = st.session_state.get("pcap_file_size")
    processing_time = st.session_state.get("processing_time")
    packet_count = result.get("packet_count", 0) if result else 0
    alert_count = len(result.get("alerts", [])) if result else 0

    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-row">
                <div>
                    <h1 class="brand">Analysis Run Overview</h1>
                    <p class="subtitle">AutoNetIR analyzes uploaded PCAP files and reports forensic IDS findings. This is not live traffic monitoring.</p>
                </div>
                <div class="status-row">
                    {status_badge(status)}
                    <span class="pill">Detection Mode: Hybrid IDS</span>
                    <span class="pill">Run: {safe_text(result.get("run_id", "No run yet") if result else "No run yet")}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    cols = st.columns(4)
    with cols[0]:
        kpi_card("PCAP File", file_name, format_bytes(file_size), "#7dd3fc")
    with cols[1]:
        kpi_card("Capture Duration", format_duration(metadata.get("capture_duration")), "First to last packet", "#22c55e")
    with cols[2]:
        kpi_card("Total Packets / Events", format_number(packet_count or metadata.get("event_count", 0)), "Parsed from uploaded PCAP", "#f8fbff")
    with cols[3]:
        kpi_card("Processing Time", format_duration(processing_time), f"{alert_count} detected alert(s)", "#f59e0b")

    cols = st.columns(2)
    with cols[0]:
        info_panel("First Packet Time", format_time(metadata.get("first_packet_time")))
    with cols[1]:
        info_panel("Last Packet Time", format_time(metadata.get("last_packet_time")))


def kpi_card(label, value, note="", color="#f8fbff"):
    st.markdown(
        f"""
        <div class="kpi">
            <div class="kpi-label">{safe_text(label)}</div>
            <div class="kpi-value" style="color:{color};">{safe_text(value)}</div>
            <div class="kpi-note">{safe_text(note)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def info_panel(title, copy):
    st.markdown(
        f"""
        <div class="panel">
            <p class="panel-title">{safe_text(title)}</p>
            <p class="panel-copy">{safe_text(copy)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def stage_statuses(result):
    if not result:
        return {stage: "Pending" for stage in PIPELINE_STAGES}
    if result.get("success"):
        return {stage: "Completed" for stage in PIPELINE_STAGES}

    statuses = {stage: "Pending" for stage in PIPELINE_STAGES}
    statuses["Upload"] = "Completed"
    first_error = (result.get("errors") or [{}])[0].get("stage", "")
    failed_stage = {
        "parser": "Parse",
        "detector": "Hybrid Correlation",
        "enrichment": "Enrichment",
        "application": "Results",
    }.get(first_error, "Results")
    for stage in PIPELINE_STAGES:
        if stage == failed_stage:
            statuses[stage] = "Failed"
            break
        statuses[stage] = "Completed"
    return statuses


def render_pipeline_summary(result):
    statuses = stage_statuses(result)
    stage_html = "".join(
        f"<span class='stage'>{safe_text(stage)} <small style='color:{status_color(status)}'>{safe_text(status)}</small></span>"
        for stage, status in statuses.items()
    )
    st.markdown(
        f"""
        <div class="panel">
            <p class="panel-title">Pipeline Execution Summary</p>
            <p class="panel-copy">Upload -> Parse -> Extract Events -> Signature Detection -> Behavior Detection -> Hybrid Correlation -> Enrichment -> Results</p>
            <div class="stage-wrap" style="margin-top:10px;">{stage_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_errors(result):
    if not result or not result.get("errors"):
        return
    st.warning("Analysis completed with warnings or failures.")
    for error in result.get("errors", []):
        with st.expander(f"{error.get('stage', 'unknown').title()} issue"):
            st.write(error)


def counts_by(alerts, field):
    return dict(Counter(str(alert.get(field) or "UNKNOWN") for alert in alerts))


def count_rows(counts, label):
    return [
        {label: key, "Count": value}
        for key, value in sorted(counts.items(), key=lambda item: item[1], reverse=True)
    ]


def counter_rows(items, label):
    return [
        {label: item[0], "Packets": item[1]}
        for item in items
        if isinstance(item, (tuple, list)) and len(item) == 2
    ]


def suspicious_hosts(alerts):
    hosts = Counter(alert.get("src_ip") for alert in alerts if alert.get("src_ip"))
    return [{"Source IP": ip, "Alert Count": count} for ip, count in hosts.most_common(10)]


def compact_host_rows(host_profiles):
    columns = [
        "src_ip",
        "packet_count",
        "unique_destinations",
        "unique_dst_ports",
        "max_unique_syn_dst_ports_per_window",
        "max_ssh_attempts_per_window",
        "max_http_login_attempts_per_window",
        "icmp_echo",
    ]
    return [{format_key(column): row.get(column, 0) for column in columns if column in row} for row in host_profiles[:25]]


def compact_pair_rows(pair_profiles):
    columns = [
        "src_ip",
        "dst_ip",
        "packet_count",
        "max_syn_no_ack_per_window",
        "max_icmp_echo_per_window",
        "unique_syn_dst_ports",
        "http_requests",
        "syn_ratio",
    ]
    return [{format_key(column): row.get(column, 0) for column in columns if column in row} for row in pair_profiles[:25]]


def attack_distribution(alerts):
    counts = Counter(alert.get("attack_type", "UNKNOWN") for alert in alerts)
    ordered_types = [
        "port_scan",
        "dos_attack",
        "arp_poisoning",
        "ssh_bruteforce",
        "http_login_bruteforce",
    ]
    rows = []
    for attack_type in ordered_types:
        rows.append({"Attack Type": attack_label(attack_type), "Alerts": counts.get(attack_type, 0)})
    for attack_type, count in counts.items():
        if attack_type not in ordered_types:
            rows.append({"Attack Type": attack_label(attack_type), "Alerts": count})
    return rows


def render_visualizations(result):
    if not result:
        return
    alerts = result.get("alerts", [])
    stats = result.get("stats", {})

    st.markdown("### PCAP Analysis Visualizations")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Protocol Distribution**")
        st.dataframe(count_rows(stats.get("protocol_counts", {}), "Protocol"), use_container_width=True, hide_index=True)
        st.markdown("**Alerts by Severity**")
        st.dataframe(count_rows(counts_by(alerts, "severity"), "Severity"), use_container_width=True, hide_index=True)
        st.markdown("**Top Source IPs**")
        st.dataframe(counter_rows(stats.get("top_sources", []), "Source IP"), use_container_width=True, hide_index=True)
    with col2:
        st.markdown("**Attack Type Distribution**")
        st.dataframe(attack_distribution(alerts), use_container_width=True, hide_index=True)
        st.markdown("**Detection Method Breakdown**")
        st.dataframe(count_rows(counts_by(alerts, "detection_method"), "Method"), use_container_width=True, hide_index=True)
        st.markdown("**Top Destination IPs**")
        st.dataframe(counter_rows(stats.get("top_destinations", []), "Destination IP"), use_container_width=True, hide_index=True)

    st.markdown("**Suspicious Hosts**")
    st.dataframe(suspicious_hosts(alerts), use_container_width=True, hide_index=True)


def summary_cards(result):
    alerts = result.get("alerts", []) if result else []
    metadata = st.session_state.get("capture_metadata", {})
    high_alerts = sum(1 for alert in alerts if alert.get("severity") == "HIGH")
    hybrid_alerts = sum(1 for alert in alerts if alert.get("detection_method") == "hybrid")
    signature_alerts = sum(1 for alert in alerts if alert.get("detection_method") == "signature")
    behavior_alerts = sum(1 for alert in alerts if alert.get("detection_method") == "behavior")
    suspicious_count = len({alert.get("src_ip") for alert in alerts if alert.get("src_ip")})

    cols = st.columns(4)
    with cols[0]:
        kpi_card("Total Packets", format_number(result.get("packet_count", 0)), "Events extracted", "#7dd3fc")
    with cols[1]:
        kpi_card("Total Alerts", format_number(len(alerts)), "Detected alerts", "#f8fbff")
    with cols[2]:
        kpi_card("High Severity", format_number(high_alerts), "Review first", severity_color("HIGH"))
    with cols[3]:
        kpi_card("Capture Duration", format_duration(metadata.get("capture_duration")), "Inside uploaded PCAP", "#22c55e")

    cols = st.columns(4)
    with cols[0]:
        kpi_card("Hybrid Alerts", format_number(hybrid_alerts), "Signature + behavior", method_color("hybrid"))
    with cols[1]:
        kpi_card("Signature-only Alerts", format_number(signature_alerts), "Known rule matched", method_color("signature"))
    with cols[2]:
        kpi_card("Behavior-only Alerts", format_number(behavior_alerts), "Peer-baseline anomaly", method_color("behavior"))
    with cols[3]:
        kpi_card("Suspicious Hosts", format_number(suspicious_count), "Unique alert sources", "#f59e0b")


def render_overview(result):
    if not result:
        render_waiting_panel()
        return
    summary_cards(result)
    render_pipeline_summary(result)
    render_visualizations(result)


def alert_window_parts(alert):
    signature = alert.get("signature_evidence", {})
    behavior = alert.get("behavior_evidence", {})
    evidence = signature or behavior
    seconds = signature.get("window_seconds") or behavior.get("window_seconds")
    start = signature.get("window_start")
    if start is None:
        start = behavior.get("window_start")
    end = signature.get("window_end")
    if end is None:
        end = behavior.get("window_end")
    return evidence, seconds, start, end


def alert_window_text(alert):
    _, seconds, start, end = alert_window_parts(alert)
    if not seconds:
        return "N/A"
    return f"{format_time(start)} -> {format_time(end)} ({seconds}s)"


def time_window_statement(alert):
    evidence, seconds, start, end = alert_window_parts(alert)
    if not seconds:
        return "No explicit time-window evidence was included for this alert."

    count_fields = [
        ("syn_no_ack_packets", "SYN packets"),
        ("unique_syn_ports", "unique ports scanned"),
        ("ssh_syn_attempts", "SSH SYN attempts"),
        ("login_post_attempts", "HTTP login POST attempts"),
        ("icmp_echo_packets", "ICMP echo packets"),
    ]
    count_text = None
    for key, label in count_fields:
        if key in evidence:
            count_text = f"{evidence[key]} {label} in {seconds} seconds"
            break
    if count_text is None:
        count_text = f"Activity exceeded the detector threshold in {seconds} seconds"

    threshold = evidence.get("threshold")
    basis = "time_window_signature" if alert.get("signature_evidence") else "time_window_behavior"
    pieces = [
        count_text,
        f"Threshold: {threshold}/window" if threshold is not None else "Threshold: behavior baseline",
        f"Window: {format_time(start)} -> {format_time(end)}",
        f"Detection Basis: {basis}",
    ]
    return "\n".join(pieces)


def normalize_alert_rows(alerts):
    rows = []
    for index, alert in enumerate(alerts, start=1):
        rows.append({
            "#": index,
            "Attack Type": alert.get("alert_type", "Unknown Attack"),
            "Severity": alert.get("severity", "UNKNOWN"),
            "Confidence": alert.get("confidence", "UNKNOWN"),
            "Detection Method": str(alert.get("detection_method", "unknown")).upper(),
            "Source IP": alert.get("src_ip") or "N/A",
            "Destination IP": alert.get("dst_ip") or "N/A",
            "Time Window / Timestamp": alert_window_text(alert),
            "Evidence Summary": alert.get("evidence", "No evidence available"),
        })
    return rows


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
            row[key] = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
        writer.writerow(row)
    return buffer.getvalue()


def filter_alerts(alerts, severity, method, attack_type, ip_search):
    filtered = list(alerts)
    if severity != "ALL":
        filtered = [alert for alert in filtered if alert.get("severity") == severity]
    if method != "ALL":
        filtered = [alert for alert in filtered if alert.get("detection_method") == method]
    if attack_type != "ALL":
        filtered = [alert for alert in filtered if alert.get("attack_type") == attack_type]
    if ip_search:
        query = ip_search.strip().lower()
        filtered = [
            alert for alert in filtered
            if query in str(alert.get("src_ip") or "").lower()
            or query in str(alert.get("dst_ip") or "").lower()
        ]
    return filtered


def render_alert_card(alert, index):
    severity = alert.get("severity", "UNKNOWN")
    method = alert.get("detection_method", "unknown")
    st.markdown(
        f"""
        <div class="alert-card" style="border-left: 6px solid {severity_color(severity)};">
            <div class="alert-head">
                <div>
                    <h3 class="alert-title">{safe_text(index)}. {safe_text(alert.get("alert_type", "Unknown Attack"))}</h3>
                    <div class="flow">{safe_text(alert.get("src_ip") or "N/A")} -> {safe_text(alert.get("dst_ip") or "N/A")}</div>
                </div>
                <div>
                    {badge(str(method).upper(), method_color(method))}
                    {badge(str(severity).upper(), severity_color(severity))}
                    {badge(str(alert.get("confidence", "UNKNOWN")).upper(), "#2563eb")}
                </div>
            </div>
            <p class="evidence">{safe_text(alert.get("evidence", "No evidence available"))}</p>
            <div class="mini-grid">
                <div class="mini"><div class="mini-label">Window</div><div class="mini-value">{safe_text(alert_window_text(alert))}</div></div>
                <div class="mini"><div class="mini-label">Attack</div><div class="mini-value">{safe_text(alert.get("attack_type", "unknown"))}</div></div>
                <div class="mini"><div class="mini-label">Score</div><div class="mini-value">{safe_text(alert.get("behavior_score", 0))}</div></div>
                <div class="mini"><div class="mini-label">Method</div><div class="mini-value">{safe_text(str(method).upper())}</div></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_field_table(value):
    if not value:
        st.caption("No data")
        return
    rows = []
    for key, item in value.items():
        rendered = json.dumps(item, ensure_ascii=False) if isinstance(item, (dict, list)) else item
        rows.append({"Field": format_key(key), "Value": rendered})
    st.dataframe(rows, use_container_width=True, hide_index=True)


def render_alert_drawer(alert):
    if not alert:
        st.markdown(
            """
            <div class="drawer">
                <div class="drawer-title">Alert Details</div>
                <p class="drawer-copy">Select an alert to inspect its forensic evidence.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    st.markdown('<div class="drawer">', unsafe_allow_html=True)
    st.markdown("### Alert Details")
    drawer_block("Alert Summary", alert.get("evidence", "No evidence available"))
    drawer_block("Source and Destination", f"{alert.get('src_ip') or 'N/A'} -> {alert.get('dst_ip') or 'N/A'}")
    drawer_block("Detection Method", str(alert.get("detection_method", "unknown")).upper())
    drawer_block("Severity and Confidence", f"{alert.get('severity', 'UNKNOWN')} / {alert.get('confidence', 'UNKNOWN')}")
    drawer_block("Time Window Evidence", time_window_statement(alert).replace("\n", "<br>"), allow_html=True)

    st.markdown("**Signature Evidence**")
    render_field_table(alert.get("signature_evidence", {}))
    st.markdown("**Behavior Evidence**")
    render_field_table(alert.get("behavior_evidence", {}))
    drawer_block("Recommendation", alert.get("recommendation", "No recommendation available"))
    drawer_block("Limitations", alert.get("limitations") or "No specific limitation.")
    if alert.get("virustotal"):
        st.markdown("**VirusTotal**")
        render_field_table(alert.get("virustotal", {}))
    st.markdown("</div>", unsafe_allow_html=True)


def drawer_block(title, copy, allow_html=False):
    content = copy if allow_html else safe_text(copy)
    st.markdown(
        f"""
        <div class="drawer-block">
            <div class="drawer-title">{safe_text(title)}</div>
            <p class="drawer-copy">{content}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_alerts(result):
    if not result:
        render_waiting_panel()
        return
    all_alerts = result.get("alerts", [])
    if not all_alerts:
        st.info("No detected alerts in this PCAP analysis.")
        return

    st.markdown("### Detected Alerts")
    attack_types = sorted({alert.get("attack_type") for alert in all_alerts if alert.get("attack_type")})
    methods = sorted({alert.get("detection_method") for alert in all_alerts if alert.get("detection_method")})
    col1, col2, col3, col4 = st.columns(4)
    severity = col1.selectbox("Severity", ["ALL", "HIGH", "MEDIUM", "LOW"])
    method = col2.selectbox("Detection Method", ["ALL"] + methods)
    attack_type = col3.selectbox("Attack Type", ["ALL"] + attack_types)
    ip_search = col4.text_input("Source/Destination IP")

    filtered = filter_alerts(all_alerts, severity, method, attack_type, ip_search)

    exp1, exp2, exp3 = st.columns([1, 1, 3])
    exp1.download_button(
        "Export JSON",
        data=json.dumps(filtered, indent=2, ensure_ascii=False),
        file_name=f"{result.get('run_id', 'autonetir')}_alerts.json",
        mime="application/json",
        use_container_width=True,
    )
    exp2.download_button(
        "Export CSV",
        data=alerts_to_csv(filtered),
        file_name=f"{result.get('run_id', 'autonetir')}_alerts.csv",
        mime="text/csv",
        use_container_width=True,
    )
    exp3.caption(f"Showing {len(filtered)} of {len(all_alerts)} detected alerts")

    if not filtered:
        st.info("No alerts match the selected filters.")
        return

    st.dataframe(normalize_alert_rows(filtered), use_container_width=True, hide_index=True)

    labels = [
        f"{i + 1}. {alert.get('alert_type', 'Unknown')} | {alert.get('src_ip') or 'N/A'} -> {alert.get('dst_ip') or 'N/A'}"
        for i, alert in enumerate(filtered)
    ]
    selected_label = st.selectbox("Open Alert Details", labels)
    selected_index = labels.index(selected_label)

    left, right = st.columns([1.45, 1])
    with left:
        for index, alert in enumerate(filtered, start=1):
            render_alert_card(alert, index)
    with right:
        render_alert_drawer(filtered[selected_index])


def render_evidence(result):
    if not result:
        render_waiting_panel()
        return
    stats = result.get("stats", {})
    summary = result.get("detection_summary", {})
    host_profiles = summary.get("host_profiles", [])
    pair_profiles = summary.get("pair_profiles", [])

    st.markdown("### PCAP Evidence Summary")
    left, right = st.columns(2)
    with left:
        st.markdown("**Protocol Distribution**")
        st.dataframe(count_rows(stats.get("protocol_counts", {}), "Protocol"), use_container_width=True, hide_index=True)
        st.markdown("**Top Source IPs**")
        st.dataframe(counter_rows(stats.get("top_sources", []), "Source IP"), use_container_width=True, hide_index=True)
    with right:
        st.markdown("**Top Destination IPs**")
        st.dataframe(counter_rows(stats.get("top_destinations", []), "Destination IP"), use_container_width=True, hide_index=True)
        st.markdown("**Suspicious Hosts**")
        st.dataframe(suspicious_hosts(result.get("alerts", [])), use_container_width=True, hide_index=True)

    st.markdown("**Host Profiles**")
    if host_profiles:
        st.dataframe(compact_host_rows(host_profiles), use_container_width=True, hide_index=True)
        with st.expander("Raw host behavior profiles"):
            st.dataframe(host_profiles, use_container_width=True)
    else:
        st.info("No host behavior profiles available.")

    st.markdown("**Flow Profiles**")
    if pair_profiles:
        st.dataframe(compact_pair_rows(pair_profiles), use_container_width=True, hide_index=True)
        with st.expander("Raw source-to-target profiles"):
            st.dataframe(pair_profiles[:100], use_container_width=True)
    else:
        st.info("No flow behavior profiles available.")


def render_engine_explanation():
    st.markdown("### Hybrid Detection Engine")
    cols = st.columns(3)
    with cols[0]:
        info_panel("Signature", "Matched a known attack rule such as SYN flood, port scan, or ARP identity conflict.")
    with cols[1]:
        info_panel("Behavior", "Abnormal compared to peer hosts or flows inside the same uploaded PCAP.")
    with cols[2]:
        info_panel("Hybrid", "Signature and behavior agree, so the alert confidence is higher.")


def render_project():
    render_engine_explanation()
    st.markdown("### Methodology")
    st.code(
        "Upload PCAP -> Parse -> Extract Events -> Signature Detection -> Behavior Detection -> Hybrid Correlation -> Enrichment -> Results",
        language="text",
    )
    st.markdown("### Attack Coverage")
    for attack in ATTACK_REGISTRY:
        limitation = attack["limitations"]
        if attack["id"] == "dos_attack":
            limitation = (
                "DoS detection is time-window based for SYN and ICMP floods. "
                "HTTP flood is disabled to reduce false positives from web responses."
            )
        st.markdown(
            f"""
            <div class="coverage-card">
                <div class="coverage-title">{safe_text(attack['name'])}</div>
                <p class="coverage-copy"><strong>Recommendation:</strong> {safe_text(attack['recommendation'])}</p>
                <p class="coverage-copy"><strong>Limitation:</strong> {safe_text(limitation)}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def main():
    inject_css()
    render_sidebar()

    result = st.session_state.get("analysis_result")
    render_header(result)
    render_errors(result)

    if result and result.get("success") is False:
        st.error("Analysis failed. Check pipeline errors and parser details.")

    render_upload_card(after_analysis=bool(result))

    overview_tab, alerts_tab, evidence_tab, project_tab = st.tabs([
        "Analysis Overview",
        "Detected Alerts",
        "PCAP Evidence",
        "Hybrid IDS",
    ])

    with overview_tab:
        render_overview(result)
    with alerts_tab:
        render_alerts(result)
    with evidence_tab:
        render_evidence(result)
    with project_tab:
        render_project()


if __name__ == "__main__":
    main()
