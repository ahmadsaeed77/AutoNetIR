from collections import defaultdict

from detection.behavior.features import is_icmp_echo, is_syn_without_ack, load_events
from detection.time_windows import DEFAULT_WINDOW_SECONDS, window_bucket, window_evidence


def detect(events_path, syn_threshold=100, icmp_threshold=100, http_threshold=None, window_seconds=DEFAULT_WINDOW_SECONDS):
    syn_counts = defaultdict(int)
    icmp_counts = defaultdict(int)

    for event in load_events(events_path):
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if not (src_ip and dst_ip):
            continue

        bucket = window_bucket(event, window_seconds)
        key = (src_ip, dst_ip, bucket)
        if event.get("transport") == "TCP" and is_syn_without_ack(event):
            dst_port = event.get("dst_port")
            if dst_port:
                syn_counts[(src_ip, dst_ip, dst_port, bucket)] += 1
        if is_icmp_echo(event):
            icmp_counts[key] += 1

    findings = []
    for (src_ip, dst_ip, dst_port, bucket), count in syn_counts.items():
        if count >= syn_threshold:
            findings.append({
                "attack_type": "dos_attack",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "signature_evidence": {
                    "dos_type": "SYN flood",
                    "dst_port": dst_port,
                    "syn_no_ack_packets": count,
                    "threshold": syn_threshold,
                    **window_evidence(bucket, window_seconds),
                },
            })

    for (src_ip, dst_ip, bucket), count in icmp_counts.items():
        if count >= icmp_threshold:
            findings.append({
                "attack_type": "dos_attack",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "signature_evidence": {
                    "dos_type": "ICMP flood",
                    "icmp_echo_packets": count,
                    "threshold": icmp_threshold,
                    **window_evidence(bucket, window_seconds),
                },
            })

    return findings
