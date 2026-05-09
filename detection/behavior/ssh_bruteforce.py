from detection.behavior.scoring import behavior_score, peer_baseline


def detect(features, min_attempts=5, min_score=60):
    hosts = features["host_profiles"]
    findings = []

    for host in hosts:
        attempts = host.get("max_ssh_attempts_per_window", host["ssh_attempts"])
        baseline = peer_baseline(hosts, "max_ssh_attempts_per_window", host["src_ip"])
        score = behavior_score(attempts, baseline["median"], minimum_reference=2)

        if attempts >= min_attempts and score >= min_score:
            findings.append({
                "attack_type": "ssh_bruteforce",
                "src_ip": host["src_ip"],
                "dst_ip": None,
                "behavior_score": score,
                "behavior_evidence": {
                    "ssh_attempts": attempts,
                    **host.get("ssh_attempts_window", {}),
                    "peer_baseline": baseline,
                    "reason": "SSH connection attempts are higher than peer behavior.",
                },
            })

    return findings
