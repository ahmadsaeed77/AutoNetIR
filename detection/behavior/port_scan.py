from detection.behavior.scoring import behavior_score, peer_baseline


def detect(features, min_ports=8, min_score=50):
    hosts = features["host_profiles"]
    findings = []

    for host in hosts:
        unique_ports = host.get("max_unique_syn_dst_ports_per_window", host["unique_syn_dst_ports"])
        baseline = peer_baseline(hosts, "max_unique_syn_dst_ports_per_window", host["src_ip"])
        score = behavior_score(unique_ports, baseline["median"], minimum_reference=4)

        if unique_ports >= min_ports and score >= min_score:
            findings.append({
                "attack_type": "port_scan",
                "src_ip": host["src_ip"],
                "dst_ip": None,
                "behavior_score": score,
                "behavior_evidence": {
                    "unique_syn_dst_ports": unique_ports,
                    **host.get("port_scan_window", {}),
                    "unique_destinations": host["unique_destinations"],
                    "peer_baseline": baseline,
                    "reason": "Destination port fan-out is higher than peer behavior.",
                },
            })

    return findings
