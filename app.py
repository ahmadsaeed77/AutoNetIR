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

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.runner import run_pipeline
from detection.hybrid.registry import ATTACK_REGISTRY
from detection.time_windows import event_timestamp
from parser.pcap_parser import get_tshark_path


st.set_page_config(
    page_title="AutoNetIR - Forensic PCAP Analysis",
    layout="wide",
    page_icon="A",
)


# ---------------------------------------------------------------------------
# Constants and mappings
# ---------------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"

PIPELINE_STAGES = [
    ("01", "Upload", "Saving PCAP to disk..."),
    ("02", "Parse", "Parsing packets with TShark..."),
    ("03", "Extract Events", "Extracting normalized network events..."),
    ("04", "Signature Detection", "Matching known attack signatures..."),
    ("05", "Behavior Detection", "Profiling host behavior inside this PCAP..."),
    ("06", "Hybrid Correlation", "Correlating signature and behavior evidence..."),
    ("07", "Enrichment", "Adding enrichment and external context..."),
    ("08", "Results", "Preparing the forensic analysis report..."),
]

CHART_COLORS = [
    "#7c3aed",
    "#a855f7",
    "#06b6d4",
    "#f59e0b",
    "#ef4444",
    "#10b981",
    "#f97316",
]

PROTOCOL_COLORS = {
    "TCP": "#06b6d4",
    "UDP": "#7c3aed",
    "ICMP": "#f97316",
    "ARP": "#f59e0b",
    "HTTP": "#a855f7",
    "HTTPS": "#10b981",
    "UNKNOWN": "#6b5fa0",
}

SEVERITY_COLORS = {
    "HIGH": "#ef4444",
    "MEDIUM": "#f59e0b",
    "LOW": "#10b981",
    "INFO": "#06b6d4",
    "UNKNOWN": "#6b5fa0",
}

METHOD_COLORS = {
    "signature": "#06b6d4",
    "behavior": "#f97316",
    "hybrid": "#a855f7",
    "unknown": "#6b5fa0",
}

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter", color="#a89cc8"),
    margin=dict(l=10, r=10, t=48, b=10),
    legend=dict(font=dict(color="#a89cc8")),
)

MITRE_MAPPING = {
    "ssh_bruteforce": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "sub_technique": "T1110.001 - Password Guessing",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Repeated SSH connection attempts can indicate brute force or password guessing activity against exposed remote access.",
    },
    "http_login_bruteforce": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "sub_technique": "T1110.001 - Password Guessing (HTTP)",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Repeated POST requests to authentication paths can indicate automated credential stuffing or login brute force attempts.",
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "sub_technique": "N/A",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Port scanning is commonly used to discover exposed services before exploitation or lateral movement.",
    },
    "arp_poisoning": {
        "tactic": "Credential Access / Lateral Movement",
        "technique": "T1557 - Adversary-in-the-Middle",
        "sub_technique": "T1557.002 - ARP Cache Poisoning",
        "url": "https://attack.mitre.org/techniques/T1557/002/",
        "description": "ARP poisoning can let an attacker intercept, modify, or disrupt local network traffic by corrupting IP-to-MAC mappings.",
    },
    "dos_attack": {
        "tactic": "Impact",
        "technique": "T1498 - Network Denial of Service",
        "sub_technique": "T1498.001 - Direct Network Flood",
        "url": "https://attack.mitre.org/techniques/T1498/001/",
        "description": "Network DoS attempts overwhelm a target service or host with traffic and can degrade availability.",
    },
}

RECOMMENDED_ACTIONS = {
    "ssh_bruteforce": [
        "Block or rate-limit the source IP at the firewall if unauthorized.",
        "Review SSH authentication logs on the target host.",
        "Enforce SSH key-based authentication and disable password login where possible.",
        "Deploy fail2ban or equivalent brute force protection.",
        "Cross-check the source IP against threat intelligence.",
    ],
    "http_login_bruteforce": [
        "Rate-limit or block the source IP at the WAF or firewall.",
        "Review web access logs for the targeted login endpoint.",
        "Enable MFA on exposed login pages.",
        "Use account lockout or step-up controls after repeated failures.",
        "Consider CAPTCHA or bot protection for public authentication paths.",
    ],
    "port_scan": [
        "Confirm whether the source is an authorized scanner.",
        "Block the source IP if the scan is unauthorized.",
        "Review discovered services and close unnecessary ports.",
        "Tighten firewall exposure for externally reachable hosts.",
        "Check whether the scan was followed by exploit or brute force attempts.",
    ],
    "arp_poisoning": [
        "Validate MAC-to-IP mappings using switch ARP tables.",
        "Enable Dynamic ARP Inspection on managed switches when available.",
        "Identify hosts that may have received poisoned ARP replies.",
        "Isolate the offending MAC address at the switch layer.",
        "Use static ARP entries for critical infrastructure when appropriate.",
    ],
    "dos_attack": [
        "Rate-limit or block the source IP at the network edge.",
        "Check service health on the targeted host.",
        "Enable SYN cookies if SYN flood behavior is present.",
        "Review firewall and load balancer telemetry for traffic volume.",
        "Escalate to upstream scrubbing if the traffic is volumetric.",
    ],
}


# ---------------------------------------------------------------------------
# CSS injection
# ---------------------------------------------------------------------------

def inject_css():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

        html, body, [data-testid="stAppViewContainer"] {
            background:
                radial-gradient(circle at top left, rgba(124, 58, 237, 0.28), transparent 34rem),
                radial-gradient(circle at top right, rgba(6, 182, 212, 0.11), transparent 30rem),
                #0a0612 !important;
            font-family: 'Inter', sans-serif !important;
            color: #f1f0ff !important;
        }

        [data-testid="stHeader"] {
            background: rgba(10, 6, 18, 0.55) !important;
            backdrop-filter: blur(12px);
        }

        .block-container {
            padding-top: 2rem !important;
            padding-bottom: 3rem !important;
            max-width: 1440px !important;
        }

        h1, h2, h3, h4, h5, h6, p, label,
        [data-testid="stMarkdownContainer"],
        [data-testid="stWidgetLabel"],
        input, textarea, button {
            font-family: 'Inter', sans-serif !important;
        }

        h1, h2, h3 {
            color: #f1f0ff !important;
            letter-spacing: 0 !important;
        }

        p, li, label, [data-testid="stMarkdownContainer"] {
            color: #a89cc8;
        }

        .glass-card {
            background: rgba(26, 16, 53, 0.72);
            backdrop-filter: blur(12px);
            border: 1px solid #2d1f5e;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 4px 24px rgba(124, 58, 237, 0.15);
            transition: all 0.2s ease;
        }

        .glass-card:hover {
            border-color: #4a3080;
            box-shadow: 0 8px 32px rgba(124, 58, 237, 0.25);
            transform: translateY(-2px);
        }

        .glow-card {
            background: linear-gradient(135deg, rgba(26, 16, 53, 0.92), rgba(10, 6, 18, 0.92));
            border: 1px solid #7c3aed;
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 0 20px rgba(124, 58, 237, 0.30), inset 0 0 20px rgba(124, 58, 237, 0.05);
            margin-bottom: 16px;
        }

        .brand-title {
            font-size: 34px;
            font-weight: 900;
            color: #f1f0ff;
            line-height: 1;
            text-shadow: 0 0 24px rgba(192, 132, 252, 0.45);
            margin: 0 0 8px 0;
        }

        .brand-subtitle {
            color: #a89cc8;
            font-size: 14px;
            font-weight: 600;
            margin: 0;
        }

        .section-title {
            color: #f1f0ff;
            font-size: 18px;
            font-weight: 800;
            margin: 0 0 12px 0;
        }

        .tiny-label {
            color: #6b5fa0;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .metric-value {
            color: #f1f0ff;
            font-size: 20px;
            font-weight: 900;
            overflow-wrap: anywhere;
        }

        .kpi-card {
            background: linear-gradient(135deg, rgba(26, 16, 53, 0.95), rgba(19, 13, 36, 0.95));
            border: 1px solid #2d1f5e;
            border-radius: 12px;
            padding: 18px 16px;
            min-height: 108px;
            transition: all 0.2s ease;
        }

        .kpi-card:hover {
            border-color: #7c3aed;
            box-shadow: 0 0 15px rgba(124, 58, 237, 0.22);
        }

        .kpi-label {
            color: #a89cc8;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 8px;
        }

        .kpi-value {
            color: #f1f0ff;
            font-size: 28px;
            font-weight: 900;
            line-height: 1.08;
            overflow-wrap: anywhere;
        }

        .kpi-note {
            color: #6b5fa0;
            font-size: 12px;
            margin-top: 6px;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            border-radius: 7px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            border: 1px solid currentColor;
            background: rgba(255, 255, 255, 0.04);
        }

        .status-completed { color: #10b981; }
        .status-failed { color: #ef4444; }
        .status-running { color: #f59e0b; }
        .status-waiting { color: #a89cc8; }

        @keyframes pulse-border {
            0%, 100% { box-shadow: 0 0 15px rgba(124, 58, 237, 0.38); }
            50% { box-shadow: 0 0 30px rgba(124, 58, 237, 0.80); }
        }

        .progress-container {
            animation: pulse-border 2s infinite;
            background: linear-gradient(135deg, #1a1035 0%, #0f0a22 100%);
            border: 1px solid #7c3aed;
            border-radius: 16px;
            padding: 30px;
            text-align: center;
            margin: 16px 0;
        }

        .progress-step {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: rgba(124, 58, 237, 0.15);
            color: #c084fc;
            border: 1px solid #7c3aed;
            font-weight: 900;
            margin-bottom: 12px;
        }

        .progress-stage-name {
            font-size: 24px;
            font-weight: 900;
            color: #c084fc;
            margin: 4px 0 6px 0;
        }

        .progress-stage-desc {
            color: #a89cc8;
            font-size: 14px;
            margin-bottom: 16px;
        }

        .stage-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
        }

        .stage-pill {
            border: 1px solid #2d1f5e;
            border-radius: 10px;
            padding: 10px;
            background: rgba(10, 6, 18, 0.45);
        }

        .stage-pill-complete {
            border-color: rgba(16, 185, 129, 0.7);
            color: #10b981;
        }

        .stage-pill-running {
            border-color: rgba(192, 132, 252, 0.9);
            color: #c084fc;
        }

        .stage-pill-pending {
            color: #6b5fa0;
        }

        .stage-pill-failed {
            border-color: rgba(239, 68, 68, 0.72);
            color: #ef4444;
        }

        [data-testid="stProgressBar"] > div > div {
            background: linear-gradient(90deg, #7c3aed, #a855f7, #c084fc) !important;
            border-radius: 4px !important;
        }

        .threat-number {
            font-size: 56px;
            font-weight: 900;
            line-height: 0.95;
            margin: 6px 0;
        }

        .threat-score-high { color: #ef4444; }
        .threat-score-medium { color: #f59e0b; }
        .threat-score-low { color: #10b981; }

        .threat-track {
            height: 12px;
            border-radius: 999px;
            background: #130d24;
            overflow: hidden;
            border: 1px solid #2d1f5e;
            margin-top: 12px;
        }

        .threat-fill {
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, #10b981, #f59e0b, #ef4444);
        }

        .severity-card {
            background: rgba(26, 16, 53, 0.72);
            border: 1px solid #2d1f5e;
            border-radius: 12px;
            padding: 18px;
            min-height: 352px;
        }

        .sev-bar-container { margin-bottom: 18px; }
        .sev-bar-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 6px;
            font-size: 13px;
            font-weight: 800;
            color: #f1f0ff;
        }
        .sev-bar-track {
            background: #130d24;
            border: 1px solid #2d1f5e;
            border-radius: 999px;
            height: 11px;
            overflow: hidden;
        }
        .sev-bar-fill {
            height: 100%;
            border-radius: 999px;
            transition: width 0.6s ease;
        }

        .evidence-box {
            background: rgba(10, 6, 18, 0.50);
            border: 1px solid #2d1f5e;
            border-radius: 12px;
            padding: 16px;
            color: #f1f0ff;
            margin-bottom: 14px;
            line-height: 1.55;
        }

        .mini-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
            margin-bottom: 14px;
        }

        .mini-cell {
            background: rgba(10, 6, 18, 0.40);
            border: 1px solid #2d1f5e;
            border-radius: 10px;
            padding: 12px;
        }

        .mitre-card {
            background: linear-gradient(135deg, rgba(124, 58, 237, 0.16), rgba(19, 13, 36, 0.90));
            border: 1px solid #4a3080;
            border-radius: 12px;
            padding: 18px;
            margin: 12px 0;
        }

        .mitre-technique-id {
            font-size: 21px;
            font-weight: 900;
            color: #c084fc;
            margin-bottom: 8px;
        }

        .action-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 0;
            border-bottom: 1px solid #1a1035;
            color: #f1f0ff;
            font-size: 14px;
        }

        .check-box {
            width: 16px;
            height: 16px;
            min-width: 16px;
            border-radius: 5px;
            border: 1px solid #7c3aed;
            background: rgba(124, 58, 237, 0.18);
            margin-top: 2px;
        }

        .warning-card {
            background: rgba(245, 158, 11, 0.09);
            border: 1px solid rgba(245, 158, 11, 0.45);
            border-radius: 12px;
            padding: 16px;
            color: #ffe6b0;
            margin-top: 12px;
        }

        .alert-shell {
            border-left: 4px solid var(--severity-color);
            border-radius: 12px;
        }

        [data-testid="stExpander"] {
            background: rgba(26, 16, 53, 0.58) !important;
            border: 1px solid #2d1f5e !important;
            border-radius: 12px !important;
            overflow: hidden !important;
        }

        [data-testid="stExpander"]:hover {
            border-color: #7c3aed !important;
            box-shadow: 0 0 18px rgba(124, 58, 237, 0.20);
        }

        [data-testid="stExpander"] summary {
            color: #f1f0ff !important;
            font-weight: 800 !important;
        }

        [data-testid="stSidebar"] {
            background: #0d0820 !important;
            border-right: 1px solid #2d1f5e !important;
        }

        [data-testid="stSidebar"] * {
            color: #f1f0ff;
        }

        [data-testid="stSidebar"] .stMarkdown p,
        [data-testid="stSidebar"] li {
            color: #a89cc8;
            font-size: 13px;
        }

        [data-testid="stTabs"] [data-baseweb="tab-list"] {
            gap: 8px;
        }

        [data-testid="stTabs"] [data-baseweb="tab"] {
            background: rgba(26, 16, 53, 0.70);
            border: 1px solid #2d1f5e;
            border-radius: 10px;
            color: #a89cc8;
            font-size: 14px;
            font-weight: 800;
            padding: 10px 16px;
        }

        [data-testid="stTabs"] [aria-selected="true"] {
            background: linear-gradient(135deg, rgba(124, 58, 237, 0.28), rgba(26, 16, 53, 0.88));
            border-color: #7c3aed;
            color: #f1f0ff;
        }

        .stButton > button, .stDownloadButton > button {
            border-radius: 9px !important;
            border: 1px solid #7c3aed !important;
            background: linear-gradient(135deg, #7c3aed, #5b21b6) !important;
            color: #f1f0ff !important;
            font-weight: 900 !important;
            transition: all 0.2s ease !important;
        }

        .stButton > button:hover, .stDownloadButton > button:hover {
            box-shadow: 0 0 18px rgba(124, 58, 237, 0.45) !important;
            transform: translateY(-1px);
        }

        .stSelectbox, .stTextInput, .stFileUploader {
            color: #f1f0ff !important;
        }

        .stDataFrame {
            border: 1px solid #2d1f5e;
            border-radius: 12px;
            overflow: hidden;
        }

        a { color: #c084fc !important; }

        @media (max-width: 900px) {
            .stage-grid, .mini-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
            .threat-number {
                font-size: 42px;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def safe_text(value, default="-"):
    if value is None or value == "":
        return default
    return html.escape(str(value))


def format_number(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "0"


def format_bytes(value):
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def format_duration(seconds):
    if seconds is None:
        return "-"
    try:
        total = float(seconds)
    except (TypeError, ValueError):
        return "-"
    if total < 0:
        return "-"
    if total < 1:
        return f"{total * 1000:.0f} ms"
    if total < 60:
        return f"{total:.2f} sec"
    minutes, sec = divmod(int(total), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    return f"{minutes}m {sec}s"


def format_time(value):
    if value is None or value == "":
        return "-"
    try:
        numeric = float(value)
        return datetime.fromtimestamp(numeric).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        pass
    text = str(value)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text


def format_key(key):
    return str(key).replace("_", " ").strip().title()


def severity_color(severity):
    return SEVERITY_COLORS.get(str(severity or "UNKNOWN").upper(), SEVERITY_COLORS["UNKNOWN"])


def method_color(method):
    return METHOD_COLORS.get(str(method or "unknown").lower(), METHOD_COLORS["unknown"])


def badge(label, color):
    label = safe_text(str(label or "UNKNOWN").upper())
    return f'<span class="badge" style="color:{color};">{label}</span>'


def section_card(title, body):
    return f"""
    <div class="glass-card">
        <div class="section-title">{safe_text(title)}</div>
        {body}
    </div>
    """


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def init_session_state():
    defaults = {
        "analysis_result": None,
        "analysis_status": "waiting",
        "pcap_file_name": None,
        "pcap_file_size": None,
        "processing_time": None,
        "capture_metadata": {},
        "analysis_timestamp": None,
        "severity_filter": "ALL",
        "method_filter": "ALL",
        "attack_filter": "ALL",
        "ip_filter": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def read_jsonl(path):
    if not path or not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
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
        ts = event_timestamp(event)
        if ts is None:
            continue
        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts

    duration = None
    if first_ts is not None and last_ts is not None:
        duration = max(0, last_ts - first_ts)

    return {
        "first_packet_time": first_ts,
        "last_packet_time": last_ts,
        "capture_duration": duration,
        "event_count": event_count or (result or {}).get("packet_count", 0),
    }


def save_uploaded_file(uploaded_file):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(uploaded_file.name).name
    destination = UPLOAD_DIR / f"{int(time.time())}_{safe_name}"
    with open(destination, "wb") as handle:
        handle.write(uploaded_file.getbuffer())
    return str(destination)


def environment_status():
    try:
        tshark_path = get_tshark_path()
        tshark_status = f"Ready: {tshark_path}"
    except Exception as error:
        tshark_status = f"Missing: {error}"

    vt_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    vt_status = "Configured" if vt_key else "Optional key not configured"
    return tshark_status, vt_status


def registry_name(attack_id):
    for attack in ATTACK_REGISTRY:
        if attack.get("id") == attack_id:
            return attack.get("name", attack_id)
    return attack_id or "Unknown"


def normalize_attack_name(alert):
    return alert.get("alert_type") or registry_name(alert.get("attack_type")) or "Unknown Alert"


def counts_by(alerts, field):
    counter = Counter()
    for alert in alerts:
        value = alert.get(field) or "unknown"
        counter[str(value)] += 1
    return counter


def suspicious_hosts(alerts):
    counter = Counter()
    for alert in alerts:
        src_ip = alert.get("src_ip")
        if src_ip:
            counter[src_ip] += 1
    return counter


def unique_sources(alerts):
    return {alert.get("src_ip") for alert in alerts if alert.get("src_ip")}


def collect_hosts_from_summary(result):
    summary = (result or {}).get("detection_summary") or {}
    hosts = summary.get("host_profiles") or []
    return {row.get("src_ip") or row.get("ip") for row in hosts if row.get("src_ip") or row.get("ip")}


def normalize_table_rows(rows, columns, rename):
    output = []
    for row in rows or []:
        normalized = {}
        for column in columns:
            label = rename.get(column, format_key(column))
            normalized[label] = row.get(column, "-")
        output.append(normalized)
    return output


def arp_identity_rows(summary):
    arp_identity = (summary or {}).get("arp_identity") or {}
    rows = []

    for ip_address, mac_values in sorted(arp_identity.items()):
        if isinstance(mac_values, str):
            macs = [mac_values]
        else:
            macs = sorted(str(mac) for mac in (mac_values or []) if mac)

        mac_count = len(set(macs))
        status = "Stable" if mac_count <= 1 else "Possible ARP Spoofing"
        rows.append({
            "IP Address": ip_address,
            "MAC Addresses": ", ".join(macs) if macs else "-",
            "MAC Count": mac_count,
            "Status": status,
        })

    return rows


def alerts_to_csv(alerts, run_id=None):
    export_run_id = run_id or "unknown"
    fields = [
        "run_id",
        "alert_type",
        "attack_type",
        "severity",
        "confidence",
        "detection_method",
        "src_ip",
        "dst_ip",
        "evidence",
        "recommendation",
        "limitations",
    ]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for alert in alerts:
        row = {field: alert.get(field, "") for field in fields}
        row["run_id"] = export_run_id
        writer.writerow(row)
    return output.getvalue()


def filter_alerts(alerts, severity, method, attack_type, ip_search):
    ip_search = (ip_search or "").strip().lower()
    filtered = []
    for alert in alerts:
        alert_severity = str(alert.get("severity") or "UNKNOWN").upper()
        alert_method = str(alert.get("detection_method") or "unknown").lower()
        alert_attack = alert.get("attack_type") or alert.get("alert_type") or "unknown"

        if severity != "ALL" and alert_severity != severity:
            continue
        if method != "ALL" and alert_method != method.lower():
            continue
        if attack_type != "ALL" and str(alert_attack) != attack_type:
            continue
        if ip_search:
            src = str(alert.get("src_ip") or "").lower()
            dst = str(alert.get("dst_ip") or "").lower()
            if ip_search not in src and ip_search not in dst:
                continue
        filtered.append(alert)
    return filtered


# ---------------------------------------------------------------------------
# Threat score
# ---------------------------------------------------------------------------

def compute_threat_score(alerts):
    if not alerts:
        return 0
    score = 0
    for alert in alerts:
        severity = str(alert.get("severity") or "").upper()
        method = str(alert.get("detection_method") or "").lower()
        if severity == "HIGH":
            score += 30
        elif severity == "MEDIUM":
            score += 15
        else:
            score += 5
        if method == "hybrid":
            score += 10
        elif method == "behavior":
            score += 5
    return min(100, score)


def threat_label(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 70:
        return "HIGH RISK"
    if score > 40:
        return "MODERATE"
    return "LOW RISK"


def threat_class(score):
    if score > 70:
        return "threat-score-high"
    if score > 40:
        return "threat-score-medium"
    return "threat-score-low"


# ---------------------------------------------------------------------------
# Upload and progress
# ---------------------------------------------------------------------------

def render_progress_stage(stage_index, status_text, progress_slot, bar_slot, log_slot):
    number, name, description = PIPELINE_STAGES[stage_index]
    percentage = (stage_index + 1) / len(PIPELINE_STAGES)

    progress_slot.markdown(
        '<div class="progress-container">'
        f'<div class="progress-step">{safe_text(number)}</div>'
        f'<div class="progress-stage-name">{safe_text(name)}</div>'
        f'<div class="progress-stage-desc">{safe_text(description)}</div>'
        f'<div class="tiny-label">{safe_text(status_text)}</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    bar_slot.progress(percentage)

    stage_cards = []
    for idx, (_, stage_name, _) in enumerate(PIPELINE_STAGES):
        if idx < stage_index:
            cls = "stage-pill stage-pill-complete"
            state = "Completed"
        elif idx == stage_index:
            cls = "stage-pill stage-pill-running"
            state = "Running"
        else:
            cls = "stage-pill stage-pill-pending"
            state = "Pending"
        stage_cards.append(
            f'<div class="{cls}">'
            f'<div class="tiny-label">{safe_text(stage_name)}</div>'
            f'<div style="font-weight:900;margin-top:4px;">{safe_text(state)}</div>'
            "</div>"
        )
    log_slot.markdown(f'<div class="stage-grid">{"".join(stage_cards)}</div>', unsafe_allow_html=True)


def run_analysis_with_progress(uploaded_file):
    st.session_state.analysis_status = "running"
    st.session_state.pcap_file_name = uploaded_file.name
    st.session_state.pcap_file_size = uploaded_file.size
    st.session_state.analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    progress_slot = st.empty()
    bar_slot = st.empty()
    log_slot = st.empty()
    result = None
    start_time = time.perf_counter()

    try:
        saved_path = None
        for idx, (_, stage_name, _) in enumerate(PIPELINE_STAGES):
            render_progress_stage(idx, "Pipeline Execution Summary", progress_slot, bar_slot, log_slot)
            time.sleep(0.45)

            if stage_name == "Upload":
                saved_path = save_uploaded_file(uploaded_file)

            if stage_name == "Hybrid Correlation":
                result = run_pipeline(saved_path)

        elapsed = time.perf_counter() - start_time
        st.session_state.processing_time = elapsed
        st.session_state.analysis_result = result
        st.session_state.capture_metadata = derive_capture_metadata(result)
        st.session_state.analysis_status = "completed" if result and result.get("success") else "failed"

        if result and result.get("success"):
            progress_slot.success("Analysis complete. Preparing dashboard...")
        else:
            progress_slot.error("Analysis failed. Preparing error details...")
        time.sleep(0.8)
        st.rerun()
    except Exception as error:
        elapsed = time.perf_counter() - start_time
        st.session_state.processing_time = elapsed
        st.session_state.analysis_status = "failed"
        st.session_state.analysis_result = {
            "success": False,
            "run_id": None,
            "packet_count": 0,
            "alerts": [],
            "stats": {},
            "detection_summary": {},
            "events_path": None,
            "errors": [
                {
                    "stage": "dashboard",
                    "message": str(error),
                    "details": traceback.format_exc(),
                }
            ],
        }
        st.session_state.capture_metadata = {}
        progress_slot.error("Analysis failed. Preparing error details...")
        time.sleep(0.8)
        st.rerun()


def render_upload_card(after_analysis=False):
    title = "Analyze Another PCAP" if after_analysis else "Drag and Drop PCAP"
    subtitle = (
        "Upload a new capture to create a fresh forensic analysis run."
        if after_analysis
        else "Upload a .pcap or .pcapng capture and run the Hybrid IDS pipeline."
    )
    st.markdown(
        f"""
        <div class="glow-card">
            <div class="brand-title">{safe_text(title)}</div>
            <p class="brand-subtitle">{safe_text(subtitle)}</p>
            <div style="margin-top:14px;">
                {badge("Supported formats: .pcap, .pcapng", "#c084fc")}
                {badge("Detection Mode: Hybrid IDS", "#06b6d4")}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Browse File",
        type=["pcap", "pcapng"],
        key="pcap_upload",
        help="Upload a PCAP or PCAPNG file for forensic analysis.",
    )
    start_disabled = uploaded_file is None or st.session_state.analysis_status == "running"
    if st.button("Start Analysis", type="primary", disabled=start_disabled, width="stretch"):
        run_analysis_with_progress(uploaded_file)


# ---------------------------------------------------------------------------
# Header and KPIs
# ---------------------------------------------------------------------------

def render_landing_header():
    st.markdown(
        """
        <div class="glow-card">
            <div class="brand-title">AutoNetIR</div>
            <p class="brand-subtitle">Purple DFIR dashboard for forensic PCAP analysis with Hybrid IDS correlation.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_badge():
    status = st.session_state.analysis_status
    if status == "completed":
        return '<span class="badge status-completed">Completed</span>'
    if status == "failed":
        return '<span class="badge status-failed">Failed</span>'
    if status == "running":
        return '<span class="badge status-running">Running</span>'
    return '<span class="badge status-waiting">Waiting</span>'


def render_kpi(label, value, note="-"):
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">{safe_text(label)}</div>
            <div class="kpi-value">{safe_text(value)}</div>
            <div class="kpi-note">{safe_text(note)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_run_overview(result):
    alerts = result.get("alerts") or []
    metadata = st.session_state.capture_metadata or {}
    score = compute_threat_score(alerts)
    score_cls = threat_class(score)
    method_counts = counts_by(alerts, "detection_method")
    high_count = sum(1 for alert in alerts if str(alert.get("severity") or "").upper() == "HIGH")
    suspicious_count = len(unique_sources(alerts) or collect_hosts_from_summary(result))
    packet_count = result.get("packet_count") or metadata.get("event_count") or 0

    left, right = st.columns([2.4, 1])
    with left:
        st.markdown(
            f"""
            <div class="glow-card">
                <div class="tiny-label">Analysis Run Overview</div>
                <div class="brand-title">AutoNetIR Forensic PCAP Analysis</div>
                <p class="brand-subtitle">Run ID: <b>{safe_text(result.get("run_id"))}</b></p>
                <div style="margin-top:14px; display:flex; gap:8px; flex-wrap:wrap;">
                    {render_status_badge()}
                    {badge("Hybrid IDS", "#06b6d4")}
                    {badge(safe_text(st.session_state.get("pcap_file_name") or "No file"), "#c084fc")}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            f"""
            <div class="glow-card">
                <div class="tiny-label">Threat Score</div>
                <div class="threat-number {score_cls}">{score}</div>
                <div class="metric-value">{safe_text(threat_label(score))}</div>
                <div class="threat-track"><div class="threat-fill" style="width:{score}%;"></div></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    kpis = st.columns(4)
    with kpis[0]:
        render_kpi("Total Packets", format_number(packet_count), "Events parsed from PCAP")
    with kpis[1]:
        render_kpi("Total Alerts", format_number(len(alerts)), "Detected alerts")
    with kpis[2]:
        render_kpi("High Severity", format_number(high_count), "Requires priority triage")
    with kpis[3]:
        render_kpi("Capture Duration", format_duration(metadata.get("capture_duration")), "First packet to last packet")

    kpis2 = st.columns(4)
    with kpis2[0]:
        render_kpi("Hybrid Alerts", format_number(method_counts.get("hybrid", 0)), "Signature + behavior")
    with kpis2[1]:
        render_kpi("Signature Alerts", format_number(method_counts.get("signature", 0)), "Known rule evidence")
    with kpis2[2]:
        render_kpi("Behavior Alerts", format_number(method_counts.get("behavior", 0)), "Peer-baseline anomaly")
    with kpis2[3]:
        render_kpi("Suspicious Hosts", format_number(suspicious_count), "Hosts tied to alerts")

    meta_cols = st.columns(4)
    with meta_cols[0]:
        render_kpi("File Size", format_bytes(st.session_state.get("pcap_file_size")), "Uploaded capture")
    with meta_cols[1]:
        render_kpi("First Packet", format_time(metadata.get("first_packet_time")), "Capture start")
    with meta_cols[2]:
        render_kpi("Last Packet", format_time(metadata.get("last_packet_time")), "Capture end")
    with meta_cols[3]:
        render_kpi("Processing Time", format_duration(st.session_state.get("processing_time")), "Pipeline runtime")


def render_pipeline_summary(failed=False):
    status = st.session_state.analysis_status
    cards = []
    for _, stage_name, _ in PIPELINE_STAGES:
        if failed:
            cls = "stage-pill stage-pill-failed"
            state = "Failed"
        elif status == "completed":
            cls = "stage-pill stage-pill-complete"
            state = "Completed"
        elif status == "running":
            cls = "stage-pill stage-pill-running"
            state = "Running"
        else:
            cls = "stage-pill stage-pill-pending"
            state = "Pending"
        cards.append(
            f'<div class="{cls}">'
            f'<div class="tiny-label">{safe_text(stage_name)}</div>'
            f'<div style="font-weight:900;margin-top:4px;">{safe_text(state)}</div>'
            "</div>"
        )
    st.markdown(
        '<div class="glass-card">'
        '<div class="section-title">Pipeline Execution Summary</div>'
        f'<div class="stage-grid">{"".join(cards)}</div>'
        "</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def empty_chart(message):
    st.markdown(
        f"""
        <div class="glass-card" style="min-height:320px;display:flex;align-items:center;justify-content:center;text-align:center;">
            <div>
                <div class="section-title">No data available</div>
                <p>{safe_text(message)}</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def donut_chart(labels, values, title, colors=None, hole=0.58):
    if not labels or not values or sum(values) == 0:
        return None
    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=hole,
                marker=dict(colors=colors or CHART_COLORS),
                textinfo="label+percent",
                hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
            )
        ]
    )
    fig.update_layout(**PLOTLY_LAYOUT, title=dict(text=title, font=dict(color="#f1f0ff", size=18)))
    return fig


def horizontal_bar_chart(rows, title, color="#7c3aed", x_title="Count"):
    clean_rows = [(str(label), int(value)) for label, value in rows if value is not None]
    if not clean_rows:
        return None
    labels = [row[0] for row in clean_rows][::-1]
    values = [row[1] for row in clean_rows][::-1]
    fig = go.Figure(
        data=[
            go.Bar(
                x=values,
                y=labels,
                orientation="h",
                marker=dict(color=color, line=dict(color="#c084fc", width=1)),
                hovertemplate="<b>%{y}</b><br>" + x_title + ": %{x}<extra></extra>",
            )
        ]
    )
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text=title, font=dict(color="#f1f0ff", size=18)),
        xaxis=dict(title=x_title, gridcolor="rgba(168,156,200,0.12)", color="#a89cc8"),
        yaxis=dict(color="#a89cc8"),
        showlegend=False,
        height=352,
    )
    return fig


def render_plotly_or_empty(fig, message):
    if fig is None:
        empty_chart(message)
    else:
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


def render_severity_breakdown(alerts):
    total = max(1, len(alerts))
    counts = counts_by(alerts, "severity")
    rows = []
    for severity in ["HIGH", "MEDIUM", "LOW"]:
        count = counts.get(severity, 0)
        percent = (count / total) * 100
        color = severity_color(severity)
        dot = (
            f'<span style="display:inline-block;width:8px;height:8px;'
            f'border-radius:999px;background:{color};margin-right:8px;"></span>'
        )
        rows.append(
            '<div class="sev-bar-container">'
            '<div class="sev-bar-label">'
            f"<span>{dot}{severity}</span>"
            f"<span>{count}</span>"
            "</div>"
            f'<div class="sev-bar-track"><div class="sev-bar-fill" style="width:{percent:.1f}%;background:{color};"></div></div>'
            "</div>"
        )
    st.markdown(
        '<div class="severity-card">'
        '<div class="section-title">Severity Breakdown</div>'
        f'{"".join(rows)}'
        '<p style="color:#6b5fa0;font-size:12px;margin-top:22px;">Percentages are based on the currently analyzed PCAP alerts.</p>'
        "</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Alert rendering
# ---------------------------------------------------------------------------

def evidence_dict(alert):
    signature = alert.get("signature_evidence") or {}
    behavior = alert.get("behavior_evidence") or {}
    return signature, behavior


def first_present(*values):
    for value in values:
        if value is not None and value != "":
            return value
    return None


def time_window_info(alert):
    signature, behavior = evidence_dict(alert)
    source = signature if signature else behavior
    window_seconds = first_present(signature.get("window_seconds"), behavior.get("window_seconds"))
    window_start = first_present(signature.get("window_start"), behavior.get("window_start"))
    window_end = first_present(signature.get("window_end"), behavior.get("window_end"))

    basis = alert.get("detection_basis") or source.get("detection_basis") or "time_window_signature"
    threshold = first_present(signature.get("threshold"), behavior.get("threshold"))

    count_keys = [
        "syn_no_ack_packets",
        "unique_syn_ports",
        "max_syn_no_ack_per_window",
        "max_unique_syn_dst_ports_per_window",
        "icmp_echo_packets",
        "http_login_attempts",
        "ssh_attempts",
        "count",
    ]
    count_text = None
    for key in count_keys:
        value = first_present(signature.get(key), behavior.get(key))
        if value is not None:
            count_text = f"{format_key(key)}: {value}"
            break

    return {
        "window_seconds": window_seconds,
        "window_start": window_start,
        "window_end": window_end,
        "threshold": threshold,
        "basis": basis,
        "count_text": count_text,
    }


def render_time_window_block(alert):
    info = time_window_info(alert)
    window_seconds = info["window_seconds"]
    window_start = info["window_start"]
    window_end = info["window_end"]
    threshold = info["threshold"]
    basis = info["basis"]
    count_text = info["count_text"] or "Windowed evidence extracted from alert fields"

    body = f"""
    <div class="evidence-box">
        <div class="tiny-label">Time Window Evidence</div>
        <div class="metric-value" style="margin-top:6px;">{safe_text(count_text)}</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;">
            {badge(f"Window: {format_time(window_start)} -> {format_time(window_end)}", "#c084fc")}
            {badge(f"Duration: {window_seconds or '-'} sec", "#06b6d4")}
            {badge(f"Threshold: {threshold if threshold is not None else '-'}", "#f59e0b")}
            {badge(f"Basis: {basis}", "#a855f7")}
        </div>
    </div>
    """
    st.markdown(body, unsafe_allow_html=True)


def evidence_rows(evidence):
    rows = []
    for key, value in (evidence or {}).items():
        if isinstance(value, (dict, list, tuple, set)):
            display = json.dumps(value, ensure_ascii=False)
        else:
            display = value
        rows.append({"Field": format_key(key), "Value": str(display)})
    return rows


def render_evidence_table(title, evidence):
    st.markdown(f"**{title}**")
    rows = evidence_rows(evidence)
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.caption("No structured evidence supplied for this section.")


def render_mitre_card(alert):
    attack_type = alert.get("attack_type")
    mapping = MITRE_MAPPING.get(attack_type)
    if not mapping:
        mapping = {
            "tactic": "Unknown",
            "technique": "Unmapped",
            "sub_technique": "N/A",
            "url": "",
            "description": "No MITRE mapping is configured for this alert type.",
        }
    url = mapping.get("url") or "#"
    st.markdown(
        f"""
        <div class="mitre-card">
            <div class="tiny-label">MITRE ATT&CK Mapping</div>
            <div class="mitre-technique-id">{safe_text(mapping.get("technique"))}</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
                {badge(mapping.get("tactic"), "#c084fc")}
                {badge(mapping.get("sub_technique"), "#06b6d4")}
            </div>
            <p>{safe_text(mapping.get("description"))}</p>
            <a href="{safe_text(url)}" target="_blank">Open MITRE reference</a>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_actions(alert):
    attack_type = alert.get("attack_type")
    actions = RECOMMENDED_ACTIONS.get(attack_type, [])
    recommendation = alert.get("recommendation")
    items = []
    if recommendation:
        items.append(f"<div class='action-item'><span class='check-box'></span><span>{safe_text(recommendation)}</span></div>")
    for action in actions:
        items.append(f"<div class='action-item'><span class='check-box'></span><span>{safe_text(action)}</span></div>")
    st.markdown(
        f"""
        <div class="glass-card">
            <div class="section-title">Recommended Actions</div>
            {''.join(items) if items else '<p>No recommendations supplied.</p>'}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_limitations(alert):
    limitation = alert.get("limitations") or alert.get("limitation") or "No limitation notes supplied for this detector."
    st.markdown(
        f"""
        <div class="warning-card">
            <div class="tiny-label">Limitations</div>
            <div style="margin-top:8px;">{safe_text(limitation)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_virustotal(alert):
    vt = alert.get("virustotal")
    if not vt:
        return
    st.markdown("**VirusTotal / Enrichment**")
    if isinstance(vt, dict):
        rows = [{"Field": format_key(k), "Value": str(v)} for k, v in vt.items()]
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.write(vt)


def expander_label(index, alert):
    severity = str(alert.get("severity") or "UNKNOWN").upper()
    method = str(alert.get("detection_method") or "unknown").upper()
    src = alert.get("src_ip") or "unknown source"
    dst = alert.get("dst_ip") or alert.get("target_ip") or "multiple/unknown targets"
    return f"[{severity}] [{method}] Alert #{index}: {normalize_attack_name(alert)} | {src} -> {dst}"


def render_alert_card(index, alert):
    severity = str(alert.get("severity") or "UNKNOWN").upper()
    method = str(alert.get("detection_method") or "unknown").lower()
    confidence = str(alert.get("confidence") or "UNKNOWN").upper()
    behavior_score = alert.get("behavior_score", "-")
    signature, behavior = evidence_dict(alert)

    with st.expander(expander_label(index, alert), expanded=index == 1):
        st.markdown(
            f"""
            <div class="evidence-box">
                <div class="tiny-label">Evidence</div>
                <div style="font-size:16px;color:#f1f0ff;margin-top:8px;">{safe_text(alert.get("evidence") or "No evidence summary supplied.")}</div>
            </div>
            <div class="mini-grid">
                <div class="mini-cell"><div class="tiny-label">Detection Method</div><div class="metric-value" style="color:{method_color(method)};">{safe_text(method.upper())}</div></div>
                <div class="mini-cell"><div class="tiny-label">Severity</div><div class="metric-value" style="color:{severity_color(severity)};">{safe_text(severity)}</div></div>
                <div class="mini-cell"><div class="tiny-label">Confidence</div><div class="metric-value">{safe_text(confidence)}</div></div>
                <div class="mini-cell"><div class="tiny-label">Behavior Score</div><div class="metric-value">{safe_text(behavior_score)}</div></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        render_time_window_block(alert)

        ev_col1, ev_col2 = st.columns(2)
        with ev_col1:
            render_evidence_table("Signature Evidence", signature)
        with ev_col2:
            render_evidence_table("Behavior Evidence", behavior)

        render_mitre_card(alert)
        render_actions(alert)
        render_limitations(alert)
        render_virustotal(alert)


# ---------------------------------------------------------------------------
# Tab 1: Alerts and detections
# ---------------------------------------------------------------------------

def init_filter_state():
    for key, default in {
        "severity_filter": "ALL",
        "method_filter": "ALL",
        "attack_filter": "ALL",
        "ip_filter": "",
    }.items():
        if key not in st.session_state:
            st.session_state[key] = default


def reset_filter_state():
    st.session_state.severity_filter = "ALL"
    st.session_state.method_filter = "ALL"
    st.session_state.attack_filter = "ALL"
    st.session_state.ip_filter = ""


def render_filter_controls(alerts):
    init_filter_state()
    attack_options = ["ALL"] + sorted({str(alert.get("attack_type") or "unknown") for alert in alerts})

    cols = st.columns([1, 1, 1.2, 1.5, 0.8])
    with cols[0]:
        st.selectbox("Severity", ["ALL", "HIGH", "MEDIUM", "LOW"], key="severity_filter")
    with cols[1]:
        st.selectbox("Detection Method", ["ALL", "hybrid", "signature", "behavior"], key="method_filter")
    with cols[2]:
        st.selectbox("Attack Type", attack_options, key="attack_filter")
    with cols[3]:
        st.text_input("Search Source/Destination IP", key="ip_filter", placeholder="192.168.1.10")
    with cols[4]:
        st.write("")
        st.write("")
        st.button("Reset Filters", on_click=reset_filter_state, width="stretch")

    return filter_alerts(
        alerts,
        st.session_state.severity_filter,
        st.session_state.method_filter,
        st.session_state.attack_filter,
        st.session_state.ip_filter,
    )


def render_alerts_tab(result):
    alerts = result.get("alerts") or []

    chart_cols = st.columns([1, 1, 1])
    with chart_cols[0]:
        attack_counts = Counter(normalize_attack_name(alert) for alert in alerts)
        fig = donut_chart(list(attack_counts.keys()), list(attack_counts.values()), "Attack Type Distribution")
        render_plotly_or_empty(fig, "No alert distribution yet.")
    with chart_cols[1]:
        source_counts = suspicious_hosts(alerts).most_common(10)
        fig = horizontal_bar_chart(source_counts, "Top Suspicious Source IPs", color="#a855f7", x_title="Alerts")
        render_plotly_or_empty(fig, "No suspicious source IPs found.")
    with chart_cols[2]:
        render_severity_breakdown(alerts)

    st.markdown(section_card("Alert Filters", "<p>Filter detections by severity, method, attack type, or IP address.</p>"), unsafe_allow_html=True)
    filtered = render_filter_controls(alerts)

    st.markdown(
        f"""
        <div class="glass-card">
            <div class="section-title">Detected Alerts</div>
            <p>Showing <b>{len(filtered)}</b> of <b>{len(alerts)}</b> alerts from this PCAP analysis run.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if filtered:
        triage_rows = []
        for idx, alert in enumerate(filtered, start=1):
            window = time_window_info(alert)
            window_text = f"{format_time(window['window_start'])} -> {format_time(window['window_end'])}"
            triage_rows.append(
                {
                    "#": idx,
                    "Attack Type": normalize_attack_name(alert),
                    "Severity": alert.get("severity", "-"),
                    "Confidence": alert.get("confidence", "-"),
                    "Detection Method": alert.get("detection_method", "-"),
                    "Source IP": alert.get("src_ip", "-"),
                    "Destination IP": alert.get("dst_ip", "-"),
                    "Time Window": window_text,
                    "Evidence Summary": alert.get("evidence", "-"),
                }
            )
        st.dataframe(triage_rows, width="stretch", hide_index=True)
    else:
        st.info("No alerts match the current filters.")

    for idx, alert in enumerate(filtered, start=1):
        render_alert_card(idx, alert)

    st.markdown("### Export Filtered Alerts")
    export_cols = st.columns(2)
    with export_cols[0]:
        st.download_button(
            "Export Alerts JSON",
            data=json.dumps(filtered, indent=2, ensure_ascii=False),
            file_name="autonetir_filtered_alerts.json",
            mime="application/json",
            width="stretch",
        )
    with export_cols[1]:
        st.download_button(
            "Export Alerts CSV",
            data=alerts_to_csv(filtered, run_id=result.get("run_id") or "unknown"),
            file_name="autonetir_filtered_alerts.csv",
            mime="text/csv",
            width="stretch",
        )


# ---------------------------------------------------------------------------
# Tab 2: PCAP intelligence
# ---------------------------------------------------------------------------

def top_rows(items, limit=15):
    rows = []
    for item in (items or [])[:limit]:
        if isinstance(item, dict):
            label = item.get("ip") or item.get("src_ip") or item.get("dst_ip") or item.get("key") or "unknown"
            value = item.get("count") or item.get("packet_count") or item.get("value") or 0
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            label, value = item[0], item[1]
        else:
            continue
        rows.append((label, value))
    return rows


def render_protocol_distribution(stats):
    protocol_counts = stats.get("protocol_counts") or {}
    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())
    colors = [PROTOCOL_COLORS.get(str(label).upper(), "#6b5fa0") for label in labels]
    fig = donut_chart(labels, values, "Protocol Distribution", colors=colors)
    render_plotly_or_empty(fig, "No protocol statistics were produced.")


def render_host_intelligence(summary):
    host_profiles = summary.get("host_profiles") or []
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
    rename = {
        "src_ip": "Source IP",
        "packet_count": "Packets",
        "unique_destinations": "Unique Destinations",
        "unique_dst_ports": "Unique Destination Ports",
        "max_unique_syn_dst_ports_per_window": "Max Scan Ports / Window",
        "max_ssh_attempts_per_window": "Max SSH Attempts / Window",
        "max_http_login_attempts_per_window": "Max HTTP Login / Window",
        "icmp_echo": "ICMP Echo",
    }
    rows = normalize_table_rows(host_profiles, columns, rename)
    st.markdown("### Host Intelligence")
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.info("No host behavior profiles were generated.")


def render_flow_intelligence(summary):
    pair_profiles = summary.get("pair_profiles") or []
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
    rename = {
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "packet_count": "Packets",
        "max_syn_no_ack_per_window": "Max SYN-No-ACK / Window",
        "max_icmp_echo_per_window": "Max ICMP Echo / Window",
        "unique_syn_dst_ports": "Unique SYN Destination Ports",
        "http_requests": "HTTP Requests",
        "syn_ratio": "SYN Ratio",
    }
    rows = normalize_table_rows(pair_profiles, columns, rename)
    st.markdown("### Flow Intelligence")
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.info("No flow behavior profiles were generated.")


def render_arp_identity_map(summary):
    rows = arp_identity_rows(summary)
    st.markdown("### ARP Identity Map")

    if not rows:
        st.info("No ARP identity data found in this capture.")
        return

    conflicts = [row for row in rows if row["MAC Count"] > 1]
    if conflicts:
        conflict_ips = ", ".join(row["IP Address"] for row in conflicts)
        st.warning(f"Possible ARP identity conflicts found for: {conflict_ips}")

    st.dataframe(rows, width="stretch", hide_index=True)


def render_capture_timeline():
    metadata = st.session_state.capture_metadata or {}
    cols = st.columns(3)
    with cols[0]:
        render_kpi("First Packet Time", format_time(metadata.get("first_packet_time")), "Capture start")
    with cols[1]:
        render_kpi("Last Packet Time", format_time(metadata.get("last_packet_time")), "Capture end")
    with cols[2]:
        render_kpi("Capture Duration", format_duration(metadata.get("capture_duration")), "Forensic time span")


def render_hybrid_engine_explanation():
    st.markdown(
        """
        <div class="glass-card">
            <div class="section-title">Hybrid Detection Engine</div>
            <div class="mini-grid">
                <div class="mini-cell"><div class="tiny-label">Signature</div><div class="metric-value" style="color:#06b6d4;">Known Rule</div><p>Matched a defined attack rule or threshold.</p></div>
                <div class="mini-cell"><div class="tiny-label">Behavior</div><div class="metric-value" style="color:#f97316;">Peer Baseline</div><p>Abnormal compared to hosts in the same PCAP.</p></div>
                <div class="mini-cell"><div class="tiny-label">Hybrid</div><div class="metric-value" style="color:#c084fc;">Correlated</div><p>Both evidence types agreed, raising confidence.</p></div>
                <div class="mini-cell"><div class="tiny-label">Scope</div><div class="metric-value">PCAP Only</div><p>This dashboard analyzes uploaded captures, not live traffic.</p></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pcap_intelligence_tab(result):
    stats = result.get("stats") or {}
    summary = result.get("detection_summary") or {}

    top_cols = st.columns([1, 1])
    with top_cols[0]:
        render_protocol_distribution(stats)
    with top_cols[1]:
        render_hybrid_engine_explanation()

    traffic_cols = st.columns(2)
    with traffic_cols[0]:
        fig = horizontal_bar_chart(top_rows(stats.get("top_sources"), limit=15), "Top Source IPs", color="#06b6d4", x_title="Packets")
        render_plotly_or_empty(fig, "No source IP statistics were produced.")
    with traffic_cols[1]:
        fig = horizontal_bar_chart(top_rows(stats.get("top_destinations"), limit=15), "Top Destination IPs", color="#7c3aed", x_title="Packets")
        render_plotly_or_empty(fig, "No destination IP statistics were produced.")

    render_host_intelligence(summary)
    render_flow_intelligence(summary)
    render_arp_identity_map(summary)

    st.markdown("### Capture Timeline")
    render_capture_timeline()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar():
    tshark_status, vt_status = environment_status()
    with st.sidebar:
        st.markdown(
            """
            <div style="padding:8px 0 18px 0;">
                <div style="font-size:28px;font-weight:900;color:#f1f0ff;text-shadow:0 0 20px rgba(192,132,252,0.7);">AutoNetIR</div>
                <div style="color:#a89cc8;font-size:13px;font-weight:700;">Purple DFIR PCAP Analysis</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("**Detection Mode**")
        st.markdown("- Hybrid IDS")
        st.markdown("- Signature detection")
        st.markdown("- Behavior baseline")
        st.markdown("- Hybrid correlation")

        st.markdown("**Supported Attacks**")
        for attack in ATTACK_REGISTRY:
            st.markdown(f"- {attack.get('name', attack.get('id'))}")

        st.markdown("**Environment**")
        st.caption(f"TShark: {tshark_status}")
        st.caption(f"VirusTotal: {vt_status}")

        result = st.session_state.get("analysis_result")
        if result:
            st.markdown("**Current Run**")
            st.caption(f"Run ID: {result.get('run_id') or '-'}")
            st.caption(f"File: {st.session_state.get('pcap_file_name') or '-'}")
            st.caption(f"Timestamp: {st.session_state.get('analysis_timestamp') or '-'}")


# ---------------------------------------------------------------------------
# Error state
# ---------------------------------------------------------------------------

def render_error_state(result):
    render_run_overview(result)
    render_pipeline_summary(failed=True)
    errors = result.get("errors") or []
    st.error("The analysis pipeline failed. Review the details below.")
    if errors:
        for idx, error in enumerate(errors, start=1):
            with st.expander(f"Error #{idx}: {error.get('stage', 'unknown')}"):
                st.json(error)
    render_upload_card(after_analysis=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    inject_css()
    init_session_state()
    render_sidebar()

    result = st.session_state.get("analysis_result")

    if not result:
        render_landing_header()
        render_upload_card(after_analysis=False)
        return

    if not result.get("success"):
        render_error_state(result)
        return

    render_run_overview(result)
    render_pipeline_summary()
    render_upload_card(after_analysis=True)

    tab_alerts, tab_pcap = st.tabs(["Alerts & Detections", "PCAP Intelligence"])
    with tab_alerts:
        render_alerts_tab(result)
    with tab_pcap:
        render_pcap_intelligence_tab(result)


if __name__ == "__main__":
    main()
