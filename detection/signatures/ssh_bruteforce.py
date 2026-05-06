from collections import defaultdict

from detection.behavior.features import is_syn_without_ack, load_events
from detection.time_windows import DEFAULT_WINDOW_SECONDS, window_bucket, window_evidence


def detect(events_path, attempt_threshold=10, window_seconds=DEFAULT_WINDOW_SECONDS):
    attempts = defaultdict(int)

    for event in load_events(events_path):
        if event.get("transport") != "TCP" or event.get("dst_port") != 22:
            continue
        if not is_syn_without_ack(event):
            continue

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if src_ip and dst_ip:
            bucket = window_bucket(event, window_seconds)
            attempts[(src_ip, dst_ip, bucket)] += 1

    findings = []
    for (src_ip, dst_ip, bucket), count in attempts.items():
        if count >= attempt_threshold:
            findings.append({
                "attack_type": "ssh_bruteforce",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "signature_evidence": {
                    "ssh_syn_attempts": count,
                    "threshold": attempt_threshold,
                    "dst_port": 22,
                    **window_evidence(bucket, window_seconds),
                },
            })

    return findings
