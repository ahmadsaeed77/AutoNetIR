from collections import defaultdict

from detection.behavior.features import load_events


def detect(events_path):
    ip_to_macs = defaultdict(set)

    for event in load_events(events_path):
        if event.get("layer") != "ARP":
            continue
        src_ip = event.get("arp_src_ip")
        src_mac = event.get("arp_src_mac")
        if src_ip and src_mac:
            ip_to_macs[src_ip].add(src_mac)

    findings = []
    for ip_address, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append({
                "attack_type": "arp_poisoning",
                "src_ip": ip_address,
                "dst_ip": None,
                "signature_evidence": {
                    "ip_address": ip_address,
                    "mac_addresses": sorted(macs),
                    "mac_count": len(macs),
                },
            })

    return findings
