from detection.alert_utils import build_hybrid_alert, confidence_from_method, severity_from_score
from detection.behavior.features import build_features
from detection.hybrid.registry import ATTACK_REGISTRY


def _finding_key(finding):
    return (
        finding.get("attack_type"),
        finding.get("src_ip"),
        finding.get("dst_ip"),
    )


def _compatible(signature_finding, behavior_finding):
    if signature_finding["attack_type"] != behavior_finding["attack_type"]:
        return False
    if signature_finding.get("src_ip") != behavior_finding.get("src_ip"):
        return False

    sig_dst = signature_finding.get("dst_ip")
    beh_dst = behavior_finding.get("dst_ip")
    return sig_dst == beh_dst or sig_dst is None or beh_dst is None


def _severity(attack_type, detection_method, behavior_score):
    if attack_type == "arp_poisoning":
        return "HIGH"
    if attack_type == "dos_attack" and detection_method in {"signature", "hybrid"}:
        return "HIGH"
    if detection_method == "signature":
        return "HIGH" if attack_type in {"port_scan", "http_login_bruteforce"} else "MEDIUM"
    return severity_from_score(behavior_score)


def _summary(attack_name, method, src_ip, dst_ip):
    target = f" targeting {dst_ip}" if dst_ip else ""
    return f"{attack_name} detected from {src_ip}{target} using {method} evidence."


def _make_alert(attack, signature_finding=None, behavior_finding=None):
    detection_method = "hybrid" if signature_finding and behavior_finding else "signature" if signature_finding else "behavior"
    source = signature_finding or behavior_finding
    src_ip = source.get("src_ip")
    dst_ip = source.get("dst_ip")
    behavior_score = 0
    behavior_evidence = {}

    if behavior_finding:
        behavior_score = behavior_finding.get("behavior_score", 0)
        behavior_evidence = behavior_finding.get("behavior_evidence", {})
        dst_ip = dst_ip or behavior_finding.get("dst_ip")

    signature_evidence = {}
    if signature_finding:
        signature_evidence = signature_finding.get("signature_evidence", {})
        dst_ip = signature_finding.get("dst_ip") or dst_ip

    severity = _severity(attack["id"], detection_method, behavior_score)
    recommendation = source.get("recommendation") or attack["recommendation"]

    return build_hybrid_alert(
        attack_type=attack["id"],
        alert_type=attack["name"],
        detection_method=detection_method,
        severity=severity,
        confidence=confidence_from_method(detection_method, behavior_score),
        src_ip=src_ip,
        dst_ip=dst_ip,
        evidence=_summary(attack["name"], detection_method, src_ip, dst_ip),
        signature_evidence=signature_evidence,
        behavior_evidence=behavior_evidence,
        behavior_score=behavior_score,
        recommendation=recommendation,
        limitations=attack["limitations"],
    )


def detect_hybrid_attacks(events_path):
    features = build_features(events_path)
    alerts = []

    for attack in ATTACK_REGISTRY:
        signature_findings = attack["signature"](events_path)
        behavior_findings = attack["behavior"](features)
        matched_behavior_keys = set()

        for signature_finding in signature_findings:
            match = None
            for behavior_finding in behavior_findings:
                if _compatible(signature_finding, behavior_finding):
                    match = behavior_finding
                    matched_behavior_keys.add(_finding_key(behavior_finding))
                    break
            alerts.append(_make_alert(attack, signature_finding, match))

        for behavior_finding in behavior_findings:
            if _finding_key(behavior_finding) not in matched_behavior_keys:
                alerts.append(_make_alert(attack, None, behavior_finding))

    return alerts


def build_detection_summary(events_path):
    return build_features(events_path)
