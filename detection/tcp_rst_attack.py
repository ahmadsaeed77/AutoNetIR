import json
from collections import defaultdict

from detection.alert_utils import build_alert
from utils.tcp_utils import has_tcp_flag

TCP_RST_FLAG = 0x04


def detect_tcp_rst_attack(events_path, rst_threshold=20, bidirectional_rst_threshold=2):
    rst_map = defaultdict(int)
    pair_map = defaultdict(int)

    with open(events_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("layer") != "IP":
                continue

            if event.get("transport") != "TCP":
                continue

            if not has_tcp_flag(event.get("tcp_flags"), TCP_RST_FLAG):
                continue

            src_ip = event.get("src_ip")
            dst_ip = event.get("dst_ip")

            if src_ip and dst_ip:
                rst_map[(src_ip, dst_ip)] += 1
                pair_map[tuple(sorted([src_ip, dst_ip]))] += 1

    alerts = []
    alerted_pairs = set()

    for (src_ip, dst_ip), count in rst_map.items():
        if count < rst_threshold:
            continue

        severity = "HIGH" if count >= rst_threshold * 3 else "MEDIUM"
        alerted_pairs.add(tuple(sorted([src_ip, dst_ip])))

        alerts.append(build_alert(
            alert_type="TCP RST Attack / Scan",
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            evidence=f"{count} TCP RST packets observed from {src_ip} to {dst_ip}",
            recommendation=(
                "Check whether resets match a legitimate closed-port scan or "
                "connection teardown. Investigate spoofing, injected resets, "
                "or unstable services if the volume is unexpected."
            ),
            confidence="MEDIUM",
            mitre_or_attack_category="Reconnaissance / Connection Reset Anomaly",
            rst_count=count,
            threshold=rst_threshold,
        ))

    for pair, count in pair_map.items():
        if pair in alerted_pairs or count < bidirectional_rst_threshold:
            continue

        src_ip, dst_ip = pair
        alerts.append(build_alert(
            alert_type="TCP RST Attack / Scan",
            severity="MEDIUM",
            src_ip=src_ip,
            dst_ip=dst_ip,
            evidence=(
                f"{count} TCP RST packets were observed between {src_ip} and {dst_ip}. "
                f"A short bidirectional reset exchange can indicate forced connection "
                f"termination or suspicious session interruption."
            ),
            recommendation=(
                "Review the surrounding packets to confirm whether the reset was "
                "expected. Investigate injected resets or unstable services if the "
                "connection ended unexpectedly."
            ),
            confidence="MEDIUM",
            mitre_or_attack_category="Connection Reset Anomaly / Session Interruption",
            rst_count=count,
            threshold=bidirectional_rst_threshold,
        ))

    return alerts
