from detection.behavior.scoring import behavior_score, peer_baseline


def _add_pair_finding(findings, pair, field, label, baseline, score, window):
    findings.append({
        "attack_type": "dos_attack",
        "src_ip": pair["src_ip"],
        "dst_ip": pair["dst_ip"],
        "behavior_score": score,
        "behavior_evidence": {
            "dos_type": label,
            field: pair[field],
            "packet_count": pair["packet_count"],
            **window,
            "unique_syn_dst_ports": pair.get("unique_syn_dst_ports", 0),
            "peer_baseline": baseline,
            "reason": f"{label} volume is higher than peer flow behavior.",
        },
    })


def detect(features, min_score=60):
    pairs = features["pair_profiles"]
    findings = []

    for pair in pairs:
        syn_count = pair.get("max_syn_no_ack_per_window", pair["syn_no_ack"])
        syn_baseline = peer_baseline(pairs, "max_syn_no_ack_per_window", pair["src_ip"])
        syn_score = behavior_score(syn_count, syn_baseline["median"], minimum_reference=20)
        if syn_count >= 50 and pair.get("unique_syn_dst_ports", 0) <= 3 and syn_score >= min_score:
            pair_with_window_count = dict(pair, syn_no_ack=syn_count)
            _add_pair_finding(
                findings,
                pair_with_window_count,
                "syn_no_ack",
                "SYN flood-like behavior",
                syn_baseline,
                syn_score,
                pair.get("syn_no_ack_window", {}),
            )

        icmp_count = pair.get("max_icmp_echo_per_window", pair["icmp_echo"])
        icmp_baseline = peer_baseline(pairs, "max_icmp_echo_per_window", pair["src_ip"])
        icmp_score = behavior_score(icmp_count, icmp_baseline["median"], minimum_reference=20)
        if icmp_count >= 50 and icmp_score >= min_score:
            pair_with_window_count = dict(pair, icmp_echo=icmp_count)
            _add_pair_finding(
                findings,
                pair_with_window_count,
                "icmp_echo",
                "ICMP flood-like behavior",
                icmp_baseline,
                icmp_score,
                pair.get("icmp_echo_window", {}),
            )

    return findings
