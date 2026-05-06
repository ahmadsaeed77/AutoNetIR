import json

from core import runner
from core.runner import calculate_detection_summary, calculate_event_stats, run_pipeline


def test_calculate_event_stats(tmp_path):
    events_path = tmp_path / "events.jsonl"
    events = [
        {"transport": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
        {"transport": "ICMP", "src_ip": "10.0.0.3", "dst_ip": "10.0.0.2"},
    ]
    with open(events_path, "w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    stats = calculate_event_stats(str(events_path))

    assert stats["packet_count"] == 2
    assert stats["protocol_counts"] == {"TCP": 1, "ICMP": 1}


def test_calculate_detection_summary(tmp_path):
    events_path = tmp_path / "events.jsonl"
    with open(events_path, "w", encoding="utf-8") as file:
        file.write(json.dumps({
            "transport": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 22,
            "tcp_flags": "0x0002",
        }) + "\n")

    summary = calculate_detection_summary(str(events_path))

    assert summary["host_profiles"][0]["ssh_attempts"] == 1


def test_run_pipeline_reports_parser_failure(tmp_path):
    result = run_pipeline(str(tmp_path / "missing.pcap"), output_root=tmp_path / "runs")

    assert result["success"] is False
    assert result["alerts"] == []
    assert result["errors"][0]["stage"] == "parser"


def test_run_pipeline_with_mocked_parser(tmp_path, monkeypatch):
    def fake_parser(pcap_path, events_path):
        with open(events_path, "w", encoding="utf-8") as file:
            for port in range(1, 16):
                file.write(json.dumps({
                    "layer": "IP",
                    "transport": "TCP",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "10.0.0.10",
                    "src_port": 40000,
                    "dst_port": port,
                    "tcp_flags": "0x0002",
                }) + "\n")
        return {"ok": True, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(runner, "run_parser", fake_parser)
    monkeypatch.setattr(runner, "enrich_alerts_with_virustotal", lambda alerts: alerts)

    result = run_pipeline("sample.pcap", output_root=tmp_path / "runs")

    assert result["success"] is True
    assert result["alerts"][0]["attack_type"] == "port_scan"
