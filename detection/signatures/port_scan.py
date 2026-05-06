from collections import defaultdict

from detection.behavior.features import is_syn_without_ack, load_events
from detection.time_windows import DEFAULT_WINDOW_SECONDS, window_bucket, window_evidence


def _flag_is_set(value):
    return str(value).strip().lower() in {"1", "true"}


def _is_syn_ack(event):
    return (
        event.get("transport") == "TCP"
        and _flag_is_set(event.get("tcp_flags_syn"))
        and _flag_is_set(event.get("tcp_flags_ack"))
    )


def _recommend_open_port_response(open_ports):
    recommendations = []

    if 22 in open_ports:
        recommendations.append("Port 22 is open; review SSH exposure and protect it against brute force attempts.")
    if 80 in open_ports:
        recommendations.append("Port 80 is open; review HTTP login endpoints, rate limiting, and DoS protections.")
    if 443 in open_ports:
        recommendations.append("Port 443 is open; HTTPS payload visibility is limited in normal PCAP analysis.")
    if len(open_ports) > 1:
        recommendations.append("Multiple open ports increase the exposed attack surface; close unused services.")

    if not recommendations:
        recommendations.append("Review the exposed services and confirm that each open port is expected.")

    return " ".join(recommendations)


def detect(events_path, port_threshold=15, window_seconds=DEFAULT_WINDOW_SECONDS):
    ports_by_source = defaultdict(set)
    targets_by_source = defaultdict(set)
    syn_flows = {}
    open_ports_by_source = defaultdict(set)

    for event in load_events(events_path):
        if event.get("transport") != "TCP":
            continue

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        src_port = event.get("src_port")
        dst_port = event.get("dst_port")

        if is_syn_without_ack(event) and src_ip and dst_ip and src_port and dst_port:
            bucket = window_bucket(event, window_seconds)
            source_key = (src_ip, bucket)
            syn_flows[(src_ip, dst_ip, src_port, dst_port)] = bucket
            ports_by_source[source_key].add(dst_port)
            targets_by_source[source_key].add(dst_ip)
            continue

        # A SYN-ACK from the target means the scanned service responded as open.
        if _is_syn_ack(event) and src_ip and dst_ip and src_port and dst_port:
            original_flow = (dst_ip, src_ip, dst_port, src_port)
            if original_flow in syn_flows:
                scanner_ip = dst_ip
                open_service_port = src_port
                source_key = (scanner_ip, syn_flows[original_flow])
                open_ports_by_source[source_key].add(open_service_port)

    findings = []
    for (src_ip, bucket), ports in ports_by_source.items():
        if len(ports) >= port_threshold:
            source_key = (src_ip, bucket)
            open_ports = sorted(open_ports_by_source[source_key])
            recommendation = _recommend_open_port_response(open_ports)
            findings.append({
                "attack_type": "port_scan",
                "src_ip": src_ip,
                "dst_ip": None,
                "recommendation": recommendation,
                "signature_evidence": {
                    "unique_syn_ports": len(ports),
                    "sample_ports": sorted(ports)[:25],
                    "target_count": len(targets_by_source[source_key]),
                    "threshold": port_threshold,
                    "open_ports": open_ports[:25],
                    "open_port_count": len(open_ports),
                    "recommendation": recommendation,
                    **window_evidence(bucket, window_seconds),
                },
            })

    return findings
