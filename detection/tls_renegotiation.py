import json
from collections import defaultdict

from detection.alert_utils import build_alert


def clean_value(value):
    """
    Normalize raw values from PyShark:
    - remove quotes
    - trim spaces
    - convert to lowercase
    """
    if value is None:
        return None

    value = str(value).strip()
    value = value.replace('"', "")
    value = value.replace("'", "")
    return value.lower()


def normalize_values(value):
    """
    Convert value into a normalized list.
    Handles single values, comma-separated values, and list values.
    """
    if value is None:
        return []

    if isinstance(value, list):
        return [clean_value(v) for v in value]

    value = clean_value(value)

    if "," in value:
        return [clean_value(v) for v in value.split(",")]

    return [value]


def is_client_hello(handshake_value):
    """
    Detect TLS ClientHello messages.

    ClientHello is the first step in a TLS handshake. Repeated ClientHello
    messages may indicate renegotiation abuse or handshake DoS behavior.
    """
    values = normalize_values(handshake_value)

    for value in values:
        if value == "1":
            return True

        if value and "client" in value and "hello" in value:
            return True

    return False


def detect_tls_renegotiation(events_path, renegotiation_threshold=3):
    """
    Detect TLS/SSL renegotiation abuse by counting repeated ClientHello
    messages between the same source and destination.
    """
    client_hello_counter = defaultdict(int)
    ports_seen = defaultdict(set)

    with open(events_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("transport") != "TCP":
                continue

            handshake_type = event.get("tls_handshake_type")

            if not is_client_hello(handshake_type):
                continue

            src_ip = event.get("src_ip")
            dst_ip = event.get("dst_ip")
            src_port = event.get("src_port")
            dst_port = event.get("dst_port")

            if not (src_ip and dst_ip):
                continue

            key = (src_ip, dst_ip)
            client_hello_counter[key] += 1

            try:
                if src_port and dst_port:
                    ports_seen[key].add((int(src_port), int(dst_port)))
            except (ValueError, TypeError):
                pass

    alerts = []

    for (src_ip, dst_ip), count in client_hello_counter.items():
        if count < renegotiation_threshold:
            continue

        sessions = len(ports_seen[(src_ip, dst_ip)])
        severity = "HIGH" if count >= renegotiation_threshold * 3 else "MEDIUM"

        alerts.append(build_alert(
            alert_type="TLS/SSL Renegotiation Abuse",
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            evidence=(
                f"{count} TLS ClientHello messages were observed from {src_ip} "
                f"to {dst_ip} across {sessions} TCP sessions. This may indicate "
                f"TLS renegotiation abuse or potential DoS behavior."
            ),
            recommendation=(
                "Verify server TLS configuration, disable insecure renegotiation "
                "where possible, and rate-limit repeated handshakes from the source."
            ),
            confidence="MEDIUM",
            mitre_or_attack_category="Denial of Service / TLS Handshake Abuse",
            client_hello_count=count,
            tcp_sessions_seen=sessions,
            threshold=renegotiation_threshold,
        ))

    return alerts
