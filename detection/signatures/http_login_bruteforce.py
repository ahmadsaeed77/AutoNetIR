from collections import defaultdict

from detection.behavior.features import is_login_request, load_events
from detection.time_windows import DEFAULT_WINDOW_SECONDS, window_bucket, window_evidence


def detect(events_path, attempt_threshold=10, window_seconds=DEFAULT_WINDOW_SECONDS):
    attempts = defaultdict(lambda: {
        "count": 0,
        "paths": set(),
        "response_codes": defaultdict(int),
        "bucket": None,
    })

    for event in load_events(events_path):
        if not is_login_request(event):
            continue

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if not (src_ip and dst_ip):
            continue

        bucket = window_bucket(event, window_seconds)
        key = (src_ip, dst_ip, bucket)
        attempts[key]["count"] += 1
        attempts[key]["bucket"] = bucket
        if event.get("http_uri"):
            attempts[key]["paths"].add(event["http_uri"])
        if event.get("http_response_code"):
            attempts[key]["response_codes"][str(event["http_response_code"])] += 1

    findings = []
    for (src_ip, dst_ip, bucket), data in attempts.items():
        if data["count"] >= attempt_threshold:
            findings.append({
                "attack_type": "http_login_bruteforce",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "signature_evidence": {
                    "login_post_attempts": data["count"],
                    "threshold": attempt_threshold,
                    "paths": sorted(data["paths"])[:10],
                    "response_codes": dict(data["response_codes"]),
                    **window_evidence(bucket, window_seconds),
                },
            })

    return findings
