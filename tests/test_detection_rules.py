import json

from detection.arp_spoofing import detect_arp_spoofing
from detection.icmp_redirect import detect_icmp_redirect_attack
from detection.icmp_tunneling import detect_icmp_tunneling
from detection.tcp_rst_attack import detect_tcp_rst_attack
from detection.tcp_syn_scan import detect_tcp_syn_port_scan
from detection.tls_renegotiation import detect_tls_renegotiation


def write_events(tmp_path, events):
    path = tmp_path / "events.jsonl"
    with open(path, "w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")
    return str(path)


def assert_standard_alert(alert):
    required = {
        "alert_type",
        "severity",
        "src_ip",
        "dst_ip",
        "evidence",
        "recommendation",
        "confidence",
        "mitre_or_attack_category",
    }
    assert required.issubset(alert)


def test_detect_arp_spoofing(tmp_path):
    events_path = write_events(tmp_path, [
        {
            "layer": "ARP",
            "arp_opcode": "2",
            "arp_src_ip": "192.168.1.1",
            "arp_src_mac": "aa:aa:aa:aa:aa:aa",
        },
        {
            "layer": "ARP",
            "arp_opcode": "2",
            "arp_src_ip": "192.168.1.1",
            "arp_src_mac": "bb:bb:bb:bb:bb:bb",
        },
    ])

    alerts = detect_arp_spoofing(events_path)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["mac_count"] == 2
    assert_standard_alert(alerts[0])


def test_detect_tcp_syn_scan(tmp_path):
    events = []
    for port in range(1, 11):
        events.append({
            "layer": "IP",
            "transport": "TCP",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.10",
            "dst_port": port,
            "tcp_flags": "0x0002",
        })
    events_path = write_events(tmp_path, events)

    alerts = detect_tcp_syn_port_scan(events_path, port_threshold=10)

    assert len(alerts) == 1
    assert alerts[0]["unique_ports"] == 10
    assert_standard_alert(alerts[0])


def test_detect_tcp_rst_attack(tmp_path):
    events = [{
        "layer": "IP",
        "transport": "TCP",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "tcp_flags": "0x0004",
    } for _ in range(20)]
    events_path = write_events(tmp_path, events)

    alerts = detect_tcp_rst_attack(events_path, rst_threshold=20)

    assert len(alerts) == 1
    assert alerts[0]["rst_count"] == 20
    assert alerts[0]["severity"] == "MEDIUM"
    assert_standard_alert(alerts[0])


def test_detect_bidirectional_tcp_rst_exchange(tmp_path):
    events_path = write_events(tmp_path, [
        {
            "layer": "IP",
            "transport": "TCP",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.10",
            "tcp_flags": "0x0014",
        },
        {
            "layer": "IP",
            "transport": "TCP",
            "src_ip": "10.0.0.10",
            "dst_ip": "10.0.0.5",
            "tcp_flags": "0x0014",
        },
    ])

    alerts = detect_tcp_rst_attack(events_path, rst_threshold=20, bidirectional_rst_threshold=2)

    assert len(alerts) == 1
    assert alerts[0]["rst_count"] == 2
    assert alerts[0]["severity"] == "MEDIUM"
    assert_standard_alert(alerts[0])


def test_detect_tls_renegotiation(tmp_path):
    events = [{
        "transport": "TCP",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "src_port": 50000 + index,
        "dst_port": 443,
        "tls_handshake_type": "1",
    } for index in range(3)]
    events_path = write_events(tmp_path, events)

    alerts = detect_tls_renegotiation(events_path, renegotiation_threshold=3)

    assert len(alerts) == 1
    assert alerts[0]["client_hello_count"] == 3
    assert_standard_alert(alerts[0])


def test_detect_icmp_redirect_attack(tmp_path):
    events = [{
        "transport": "ICMP",
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.50",
        "icmp_type": "5",
        "icmp_gateway": "192.168.1.254",
    } for _ in range(5)]
    events_path = write_events(tmp_path, events)

    alerts = detect_icmp_redirect_attack(events_path, threshold=5)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["gateway_ips"] == ["192.168.1.254"]
    assert_standard_alert(alerts[0])


def test_detect_icmp_tunneling(tmp_path):
    events = [{
        "transport": "ICMP",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "icmp_type": "8",
        "ip_len": 160,
    } for _ in range(25)]
    events_path = write_events(tmp_path, events)

    alerts = detect_icmp_tunneling(events_path, packet_threshold=25, avg_size_threshold=120)

    assert len(alerts) == 1
    assert alerts[0]["icmp_packet_count"] == 25
    assert alerts[0]["average_packet_length"] == 160
    assert_standard_alert(alerts[0])
