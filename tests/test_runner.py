import json

from core.runner import calculate_event_stats, run_pipeline, selected_detectors


def test_selected_detectors_can_filter_by_id():
    detectors = selected_detectors(enabled_detectors=["tcp_syn_scan"])

    assert len(detectors) == 1
    assert detectors[0]["id"] == "tcp_syn_scan"


def test_calculate_event_stats(tmp_path):
    events_path = tmp_path / "events.jsonl"
    events = [
        {"transport": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
        {"transport": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3"},
        {"transport": "ICMP", "src_ip": "10.0.0.4", "dst_ip": "10.0.0.2"},
    ]
    with open(events_path, "w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    stats = calculate_event_stats(str(events_path))

    assert stats["packet_count"] == 3
    assert stats["protocol_counts"] == {"TCP": 2, "ICMP": 1}
    assert stats["top_sources"][0] == ("10.0.0.1", 2)


def test_run_pipeline_reports_parser_failure(tmp_path):
    result = run_pipeline(str(tmp_path / "missing.pcap"), output_root=tmp_path / "runs")

    assert result["success"] is False
    assert result["alerts"] == []
    assert result["errors"][0]["stage"] == "parser"
