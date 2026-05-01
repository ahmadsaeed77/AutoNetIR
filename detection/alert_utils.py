def build_alert(
    alert_type,
    severity,
    evidence,
    recommendation,
    confidence,
    mitre_or_attack_category,
    src_ip=None,
    dst_ip=None,
    **details,
):
    """Create a consistent alert shape for every detector."""
    alert = {
        "alert_type": alert_type,
        "severity": str(severity).upper(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
        "mitre_or_attack_category": mitre_or_attack_category,
    }

    for key, value in details.items():
        if value is not None:
            alert[key] = value

    return alert
