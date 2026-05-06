def detect(features):
    findings = []

    for host in features["host_profiles"]:
        mac_count = host.get("arp_mac_count", 0)
        if mac_count > 1:
            findings.append({
                "attack_type": "arp_poisoning",
                "src_ip": host["src_ip"],
                "dst_ip": None,
                "behavior_score": 100,
                "behavior_evidence": {
                    "arp_mac_count": mac_count,
                    "mac_addresses": host.get("arp_mac_addresses", []),
                    "reason": "The same IP address is associated with multiple MAC addresses.",
                },
            })

    return findings
