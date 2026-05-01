import json
from collections import defaultdict

from detection.alert_utils import build_alert

ICMP_ECHO_TYPES = {"0", "8"}


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def detect_icmp_tunneling(events_path, packet_threshold=25, avg_size_threshold=120):
    """
    Detect ICMP tunneling/anomaly behavior.

    Tunneling tools often generate many ICMP echo packets between the same
    hosts, commonly with unusually large or consistent packet lengths.
    """
    flow_counts = defaultdict(int)
    flow_lengths = defaultdict(list)
    type_counts = defaultdict(lambda: defaultdict(int))

    with open(events_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("transport") != "ICMP":
                continue

            src_ip = event.get("src_ip")
            dst_ip = event.get("dst_ip")
            icmp_type = str(event.get("icmp_type"))

            if not (src_ip and dst_ip):
                continue

            if icmp_type not in ICMP_ECHO_TYPES:
                continue

            key = (src_ip, dst_ip)
            flow_counts[key] += 1
            type_counts[key][icmp_type] += 1

            length = _to_int(event.get("ip_len")) or _to_int(event.get("frame_len"))
            if length:
                flow_lengths[key].append(length)

    alerts = []

    for (src_ip, dst_ip), count in flow_counts.items():
        lengths = flow_lengths[(src_ip, dst_ip)]
        avg_size = round(sum(lengths) / len(lengths), 2) if lengths else 0

        if count < packet_threshold and avg_size < avg_size_threshold:
            continue

        severity = "HIGH" if count >= packet_threshold * 2 else "MEDIUM"
        confidence = "HIGH" if count >= packet_threshold and avg_size >= avg_size_threshold else "MEDIUM"

        alerts.append(build_alert(
            alert_type="ICMP Tunneling / Anomaly",
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            evidence=(
                f"{count} ICMP echo packets observed from {src_ip} to {dst_ip} "
                f"with average packet length {avg_size}. This may indicate ICMP "
                f"tunneling, covert channel activity, or ping-based data transfer."
            ),
            recommendation=(
                "Review whether ICMP echo traffic is expected, inspect payload sizes, "
                "and restrict ICMP echo traffic across network boundaries if suspicious."
            ),
            confidence=confidence,
            mitre_or_attack_category="Command and Control / Protocol Tunneling",
            icmp_packet_count=count,
            average_packet_length=avg_size,
            icmp_type_counts=dict(type_counts[(src_ip, dst_ip)]),
            packet_threshold=packet_threshold,
            average_size_threshold=avg_size_threshold,
        ))

    return alerts
