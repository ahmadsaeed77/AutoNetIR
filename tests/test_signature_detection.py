from detection.signatures import arp_poisoning, dos_attack, http_login_bruteforce, port_scan, ssh_bruteforce
from tests.helpers import http_get, http_login_post, tcp_syn, tcp_syn_ack, write_events


def test_ssh_bruteforce_signature(tmp_path):
    events_path = write_events(tmp_path, [tcp_syn("10.0.0.5", "10.0.0.10", 22, timestamp=10) for _ in range(10)])

    alerts = ssh_bruteforce.detect(events_path)

    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "ssh_bruteforce"
    assert alerts[0]["signature_evidence"]["window_seconds"] == 60


def test_ssh_bruteforce_signature_requires_attempts_inside_one_window(tmp_path):
    events_path = write_events(tmp_path, [
        tcp_syn("10.0.0.5", "10.0.0.10", 22, timestamp=index * 61)
        for index in range(10)
    ])

    alerts = ssh_bruteforce.detect(events_path)

    assert alerts == []


def test_http_login_bruteforce_signature(tmp_path):
    events = [http_login_post("10.0.0.5", "10.0.0.10", timestamp=10) for _ in range(10)]
    events_path = write_events(tmp_path, events)

    alerts = http_login_bruteforce.detect(events_path)

    assert len(alerts) == 1
    assert alerts[0]["signature_evidence"]["login_post_attempts"] == 10
    assert alerts[0]["signature_evidence"]["window_seconds"] == 60


def test_port_scan_signature(tmp_path):
    events_path = write_events(tmp_path, [tcp_syn("10.0.0.5", "10.0.0.10", port, timestamp=10) for port in range(1, 16)])

    alerts = port_scan.detect(events_path)

    assert len(alerts) == 1
    assert alerts[0]["signature_evidence"]["unique_syn_ports"] == 15
    assert alerts[0]["signature_evidence"]["window_seconds"] == 60


def test_port_scan_signature_requires_ports_inside_one_window(tmp_path):
    events_path = write_events(tmp_path, [
        tcp_syn("10.0.0.5", "10.0.0.10", port, timestamp=port * 61)
        for port in range(1, 16)
    ])

    alerts = port_scan.detect(events_path)

    assert alerts == []


def test_port_scan_signature_reports_open_ports_and_recommendation(tmp_path):
    scanned_ports = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 22, 80, 443]
    events = [tcp_syn("10.0.0.5", "10.0.0.10", port) for port in scanned_ports]
    events.extend([
        tcp_syn_ack("10.0.0.10", "10.0.0.5", 22, 40000),
        tcp_syn_ack("10.0.0.10", "10.0.0.5", 80, 40000),
        tcp_syn_ack("10.0.0.10", "10.0.0.5", 443, 40000),
    ])
    events_path = write_events(tmp_path, events)

    alerts = port_scan.detect(events_path)

    evidence = alerts[0]["signature_evidence"]
    assert evidence["open_ports"] == [22, 80, 443]
    assert evidence["open_port_count"] == 3
    assert "SSH" in alerts[0]["recommendation"]
    assert "HTTP" in alerts[0]["recommendation"]
    assert "HTTPS" in alerts[0]["recommendation"]


def test_arp_poisoning_signature(tmp_path):
    events_path = write_events(tmp_path, [
        {"layer": "ARP", "arp_src_ip": "192.168.1.1", "arp_src_mac": "aa:aa:aa:aa:aa:aa"},
        {"layer": "ARP", "arp_src_ip": "192.168.1.1", "arp_src_mac": "bb:bb:bb:bb:bb:bb"},
    ])

    alerts = arp_poisoning.detect(events_path)

    assert len(alerts) == 1
    assert alerts[0]["signature_evidence"]["mac_count"] == 2


def test_dos_signature(tmp_path):
    events_path = write_events(tmp_path, [tcp_syn("10.0.0.5", "10.0.0.10", 80, timestamp=10) for _ in range(100)])

    alerts = dos_attack.detect(events_path)

    assert len(alerts) == 1
    assert alerts[0]["signature_evidence"]["dos_type"] == "SYN flood"
    assert alerts[0]["signature_evidence"]["dst_port"] == 80
    assert alerts[0]["signature_evidence"]["window_start"] == 0
    assert alerts[0]["signature_evidence"]["window_end"] == 60


def test_dos_signature_requires_threshold_inside_one_window(tmp_path):
    events_path = write_events(tmp_path, [
        tcp_syn("10.0.0.5", "10.0.0.10", 80, timestamp=index * 61)
        for index in range(100)
    ])

    alerts = dos_attack.detect(events_path)

    assert alerts == []


def test_http_traffic_does_not_trigger_dos_signature(tmp_path):
    events_path = write_events(tmp_path, [http_get("10.0.0.5", "10.0.0.10", timestamp=10) for _ in range(150)])

    alerts = dos_attack.detect(events_path)

    assert alerts == []


def test_http_login_bruteforce_requires_threshold_inside_one_window(tmp_path):
    events_path = write_events(tmp_path, [
        http_login_post("10.0.0.5", "10.0.0.10", timestamp=index * 61)
        for index in range(10)
    ])

    alerts = http_login_bruteforce.detect(events_path)

    assert alerts == []


def test_port_scan_syns_do_not_trigger_dos_signature(tmp_path):
    events_path = write_events(tmp_path, [tcp_syn("10.0.0.5", "10.0.0.10", port) for port in range(1, 101)])

    alerts = dos_attack.detect(events_path)

    assert alerts == []
