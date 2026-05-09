import csv
import io

from app import alerts_to_csv, arp_identity_rows


def test_alerts_to_csv_includes_run_id():
    alerts = [{
        "attack_type": "port_scan",
        "alert_type": "Port Scanning",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "hybrid",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "evidence": "test evidence",
        "recommendation": "test recommendation",
        "limitations": "test limitation",
    }]

    rows = list(csv.DictReader(io.StringIO(alerts_to_csv(alerts, run_id="run-123"))))

    assert rows[0]["run_id"] == "run-123"
    assert rows[0]["attack_type"] == "port_scan"


def test_arp_identity_rows_marks_stable_and_conflict():
    rows = arp_identity_rows({
        "arp_identity": {
            "192.168.1.1": ["aa:aa:aa:aa:aa:aa"],
            "192.168.1.10": ["bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"],
        }
    })

    by_ip = {row["IP Address"]: row for row in rows}

    assert by_ip["192.168.1.1"]["MAC Count"] == 1
    assert by_ip["192.168.1.1"]["Status"] == "Stable"
    assert by_ip["192.168.1.10"]["MAC Count"] == 2
    assert by_ip["192.168.1.10"]["Status"] == "Possible ARP Spoofing"
