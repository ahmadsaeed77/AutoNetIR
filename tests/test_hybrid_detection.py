from detection.hybrid import detector
from detection.hybrid.detector import detect_hybrid_attacks
from tests.helpers import tcp_syn, write_events


def test_hybrid_alert_when_signature_and_behavior_match(tmp_path):
    events = [tcp_syn("10.0.0.5", "10.0.0.10", port) for port in range(1, 16)]
    events.append(tcp_syn("10.0.0.6", "10.0.0.10", 443))
    events_path = write_events(tmp_path, events)

    alerts = detect_hybrid_attacks(events_path)

    port_alert = next(alert for alert in alerts if alert["attack_type"] == "port_scan")
    assert port_alert["detection_method"] == "hybrid"
    assert port_alert["signature_evidence"]
    assert port_alert["behavior_evidence"]


def test_behavior_only_alert(tmp_path):
    events = [tcp_syn("10.0.0.5", "10.0.0.10", 22) for _ in range(5)]
    events.append(tcp_syn("10.0.0.6", "10.0.0.10", 22))
    events_path = write_events(tmp_path, events)

    alerts = detect_hybrid_attacks(events_path)

    ssh_alert = next(alert for alert in alerts if alert["attack_type"] == "ssh_bruteforce")
    assert ssh_alert["detection_method"] == "behavior"


def test_signature_only_alert_with_custom_registry(tmp_path, monkeypatch):
    events_path = write_events(tmp_path, [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.10"}])

    monkeypatch.setattr(detector, "ATTACK_REGISTRY", [{
        "id": "custom_attack",
        "name": "Custom Attack",
        "signature": lambda path: [{
            "attack_type": "custom_attack",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.10",
            "signature_evidence": {"matched": True},
        }],
        "behavior": lambda features: [],
        "recommendation": "Investigate.",
        "limitations": "Test limitation.",
    }])

    alerts = detect_hybrid_attacks(events_path)

    assert alerts[0]["detection_method"] == "signature"


def test_large_port_scan_does_not_create_dos_alert(tmp_path):
    events_path = write_events(tmp_path, [tcp_syn("10.0.0.5", "10.0.0.10", port) for port in range(1, 101)])

    alerts = detect_hybrid_attacks(events_path)
    attack_types = [alert["attack_type"] for alert in alerts]

    assert "port_scan" in attack_types
    assert "dos_attack" not in attack_types
