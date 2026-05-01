import json
from collections import defaultdict
from detection.alert_utils import build_alert

ARP_REPLY_OPCODE = "2"


def detect_arp_spoofing(events_path):
    """
    Detect ARP spoofing by identifying IP addresses that are associated
    with more than one MAC address in ARP reply packets.
    """
    ip_mac_map = defaultdict(set)

    with open(events_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("layer") != "ARP":
                continue

            opcode = str(event.get("arp_opcode"))

            # ARP opcode 2 means ARP Reply.
            # ARP replies are more reliable for detecting IP-MAC conflicts.
            if opcode != ARP_REPLY_OPCODE:
                continue

            src_ip = event.get("arp_src_ip")
            src_mac = event.get("arp_src_mac")

            if src_ip and src_mac:
                ip_mac_map[src_ip].add(src_mac)

    alerts = []

    for ip_address, mac_addresses in ip_mac_map.items():
        if len(mac_addresses) > 1:
            mac_list = sorted(mac_addresses)

            alerts.append(build_alert(
                alert_type="ARP Spoofing",
                severity="HIGH",
                src_ip=ip_address,
                evidence=(
                    f"IP address {ip_address} was observed with multiple "
                    f"MAC addresses: {mac_list}. This may indicate ARP spoofing "
                    f"or ARP poisoning activity."
                ),
                recommendation=(
                    "Verify the legitimate MAC address for this IP, inspect the "
                    "switch ARP table, and consider enabling Dynamic ARP Inspection."
                ),
                confidence="HIGH",
                mitre_or_attack_category="Man-in-the-Middle / ARP Poisoning",
                ip=ip_address,
                mac_addresses=mac_list,
                mac_count=len(mac_list),
            ))

    return alerts
