import json
from collections import defaultdict

from detection.alert_utils import build_alert

ICMP_REDIRECT_TYPE = "5"


def detect_icmp_redirect_attack(events_path, threshold=5):
    """
    Detect ICMP Redirect abuse.

    ICMP Redirect (Type 5) can be used by routers to announce a better route.
    Attackers can abuse it to redirect traffic through a malicious gateway.
    """
    redirect_counter = defaultdict(int)
    gateway_map = defaultdict(set)

    with open(events_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("transport") != "ICMP":
                continue

            if str(event.get("icmp_type")) != ICMP_REDIRECT_TYPE:
                continue

            src_ip = event.get("src_ip")
            dst_ip = event.get("dst_ip")
            gateway_ip = event.get("icmp_gateway")

            if not (src_ip and dst_ip):
                continue

            key = (src_ip, dst_ip)
            redirect_counter[key] += 1

            if gateway_ip:
                gateway_map[key].add(str(gateway_ip).strip())

    alerts = []

    for (src_ip, dst_ip), count in redirect_counter.items():
        if count < threshold:
            continue

        gateways = sorted(list(gateway_map[(src_ip, dst_ip)]))
        severity = "MEDIUM"
        confidence = "MEDIUM"
        evidence = f"{count} ICMP Redirect messages detected from {src_ip} to {dst_ip}."

        if any(gateway != src_ip for gateway in gateways):
            severity = "HIGH"
            confidence = "HIGH"
            evidence = (
                f"{count} ICMP Redirect messages detected from {src_ip} to {dst_ip}. "
                f"Redirected gateway differs from sender IP. Gateways observed: {gateways}. "
                f"This may indicate traffic redirection or MITM attack."
            )

        if len(gateways) > 1:
            severity = "HIGH"
            confidence = "HIGH"
            evidence = (
                f"{count} ICMP Redirect messages detected from {src_ip} to {dst_ip} "
                f"with multiple gateway IPs: {gateways}. This indicates possible "
                f"route manipulation or MITM attack."
            )

        alerts.append(build_alert(
            alert_type="ICMP Redirect Attack",
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            evidence=evidence,
            recommendation=(
                "Validate the legitimate default gateway, block suspicious ICMP "
                "redirects at hosts or network controls, and inspect routing changes."
            ),
            confidence=confidence,
            mitre_or_attack_category="Man-in-the-Middle / Route Manipulation",
            redirect_count=count,
            gateway_ips=gateways,
            threshold=threshold,
        ))

    return alerts
