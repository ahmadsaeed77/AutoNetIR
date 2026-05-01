import json
from collections import defaultdict
from detection.alert_utils import build_alert
from utils.tcp_utils import has_tcp_flag

TCP_SYN_FLAG = 0x02
TCP_ACK_FLAG = 0x10


def detect_tcp_syn_port_scan(events_path, port_threshold=10):
    scan_map = defaultdict(set)

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

            tcp_flags = event.get("tcp_flags")

            syn_set = has_tcp_flag(tcp_flags, TCP_SYN_FLAG)
            ack_set = has_tcp_flag(tcp_flags, TCP_ACK_FLAG)

            if syn_set and not ack_set:
                src_ip = event.get("src_ip")
                dst_ip = event.get("dst_ip")
                dst_port = event.get("dst_port")

                try:
                    dst_port = int(dst_port)
                except (TypeError, ValueError):
                    continue

                if src_ip and dst_ip:
                    scan_map[(src_ip, dst_ip)].add(dst_port)

    alerts = []

    for (src_ip, dst_ip), ports in scan_map.items():
        if len(ports) >= port_threshold:
            alerts.append(build_alert(
                alert_type="TCP SYN Port Scan",
                severity="HIGH",
                src_ip=src_ip,
                dst_ip=dst_ip,
                evidence=(
                    f"{src_ip} sent SYN packets to {len(ports)} different ports on {dst_ip}"
                ),
                recommendation=(
                    "Confirm whether this source is an approved scanner. If not, "
                    "block or isolate it and review exposed services on the target."
                ),
                confidence="HIGH",
                mitre_or_attack_category="Reconnaissance / Network Service Discovery",
                unique_ports=len(ports),
                ports=sorted(list(ports)),
                threshold=port_threshold,
            ))

    return alerts
