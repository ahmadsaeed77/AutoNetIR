from detection.behavior import arp_poisoning, dos_attack, http_login_bruteforce, port_scan, ssh_bruteforce
from detection.behavior.features import build_features
from tests.helpers import http_get, tcp_syn, write_events


def test_port_scan_behavior(tmp_path):
    events = [tcp_syn("10.0.0.5", "10.0.0.10", port) for port in range(1, 9)]
    events.extend([tcp_syn("10.0.0.6", "10.0.0.10", 443)])
    features = build_features(write_events(tmp_path, events))

    alerts = port_scan.detect(features)

    assert len(alerts) == 1
    assert alerts[0]["behavior_score"] >= 50


def test_ssh_bruteforce_behavior(tmp_path):
    events = [tcp_syn("10.0.0.5", "10.0.0.10", 22) for _ in range(5)]
    events.append(tcp_syn("10.0.0.6", "10.0.0.10", 22))
    features = build_features(write_events(tmp_path, events))

    alerts = ssh_bruteforce.detect(features)

    assert len(alerts) == 1


def test_http_login_behavior(tmp_path):
    events = [{
        "transport": "TCP",
        "app_protocol": "HTTP",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "http_method": "POST",
        "http_uri": "/admin/login",
    } for _ in range(5)]
    events.append({
        "transport": "TCP",
        "app_protocol": "HTTP",
        "src_ip": "10.0.0.6",
        "dst_ip": "10.0.0.10",
        "http_method": "GET",
        "http_uri": "/",
    })
    features = build_features(write_events(tmp_path, events))

    alerts = http_login_bruteforce.detect(features)

    assert len(alerts) == 1


def test_arp_behavior(tmp_path):
    events_path = write_events(tmp_path, [
        {"layer": "ARP", "arp_src_ip": "192.168.1.1", "arp_src_mac": "aa:aa:aa:aa:aa:aa"},
        {"layer": "ARP", "arp_src_ip": "192.168.1.1", "arp_src_mac": "bb:bb:bb:bb:bb:bb"},
    ])
    features = build_features(events_path)

    alerts = arp_poisoning.detect(features)

    assert len(alerts) == 1
    assert alerts[0]["behavior_score"] == 100


def test_dos_behavior(tmp_path):
    events = [tcp_syn("10.0.0.5", "10.0.0.10", 80, timestamp=10) for _ in range(50)]
    events.append(tcp_syn("10.0.0.6", "10.0.0.10", 80, timestamp=10))
    features = build_features(write_events(tmp_path, events))

    alerts = dos_attack.detect(features)

    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "dos_attack"
    assert alerts[0]["behavior_evidence"]["window_seconds"] == 60


def test_dos_behavior_requires_volume_inside_one_window(tmp_path):
    events = [
        tcp_syn("10.0.0.5", "10.0.0.10", 80, timestamp=index * 61)
        for index in range(50)
    ]
    events.append(tcp_syn("10.0.0.6", "10.0.0.10", 80, timestamp=10))
    features = build_features(write_events(tmp_path, events))

    alerts = dos_attack.detect(features)

    assert alerts == []


def test_http_traffic_does_not_create_dos_behavior(tmp_path):
    events = [http_get("10.0.0.5", "10.0.0.10", timestamp=10) for _ in range(150)]
    features = build_features(write_events(tmp_path, events))

    alerts = dos_attack.detect(features)

    assert alerts == []


def test_port_scan_syns_do_not_create_dos_behavior(tmp_path):
    events = [tcp_syn("10.0.0.5", "10.0.0.10", port) for port in range(1, 51)]
    events.append(tcp_syn("10.0.0.6", "10.0.0.10", 80))
    features = build_features(write_events(tmp_path, events))

    alerts = dos_attack.detect(features)

    assert alerts == []


def test_normal_traffic_does_not_create_behavior_alerts(tmp_path):
    events_path = write_events(tmp_path, [
        {"transport": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "tcp_flags": "0x0010"},
        {"transport": "TCP", "src_ip": "10.0.0.3", "dst_ip": "10.0.0.2", "dst_port": 443, "tcp_flags": "0x0010"},
    ])
    features = build_features(events_path)

    assert port_scan.detect(features) == []
    assert ssh_bruteforce.detect(features) == []
    assert dos_attack.detect(features) == []
