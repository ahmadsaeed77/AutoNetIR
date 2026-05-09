from datetime import datetime

def build_hybrid_alert(
    attack_type,
    alert_type,
    detection_method,
    severity,
    confidence,
    evidence,
    recommendation,
    src_ip=None,
    dst_ip=None,
    signature_evidence=None,
    behavior_evidence=None,
    behavior_score=0,
    limitations=None,
):
    return {
        "attack_type": attack_type,
        "alert_type": alert_type,
        "detection_method": detection_method,
        "severity": str(severity).upper(),
        "confidence": str(confidence).upper(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "evidence": evidence,
        "signature_evidence": signature_evidence or {},
        "behavior_evidence": behavior_evidence or {},
        "behavior_score": behavior_score,
        "recommendation": recommendation,
        "limitations": limitations or "",
        "detected_at": datetime.utcnow().isoformat() + "Z",
    }


def severity_from_score(score):
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def confidence_from_method(detection_method, score=0):
    if detection_method == "hybrid":
        return "HIGH" if score >= 70 else "MEDIUM"
    if detection_method == "signature":
        return "HIGH"
    return "MEDIUM" if score >= 60 else "LOW"
