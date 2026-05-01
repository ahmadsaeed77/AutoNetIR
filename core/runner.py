import json
import logging
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from detection.arp_spoofing import detect_arp_spoofing
from detection.icmp_redirect import detect_icmp_redirect_attack
from detection.icmp_tunneling import detect_icmp_tunneling
from detection.tcp_rst_attack import detect_tcp_rst_attack
from detection.tcp_syn_scan import detect_tcp_syn_port_scan
from detection.tls_renegotiation import detect_tls_renegotiation
from enrichment.virustotal_lookup import enrich_alerts_with_virustotal

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


DETECTOR_REGISTRY = [
    {
        "id": "arp_spoofing",
        "name": "ARP Spoofing",
        "function": detect_arp_spoofing,
        "enabled": True,
        "kwargs": {},
        "description": "Detects one IP address being advertised by multiple MAC addresses.",
    },
    {
        "id": "tcp_syn_scan",
        "name": "TCP SYN Port Scan",
        "function": detect_tcp_syn_port_scan,
        "enabled": True,
        "kwargs": {"port_threshold": 10},
        "description": "Detects many SYN packets from one source to many destination ports.",
    },
    {
        "id": "tcp_rst_attack",
        "name": "TCP RST Attack / Scan",
        "function": detect_tcp_rst_attack,
        "enabled": True,
        "kwargs": {"rst_threshold": 20, "bidirectional_rst_threshold": 2},
        "description": "Detects high TCP reset volume between a source and destination.",
    },
    {
        "id": "tls_renegotiation",
        "name": "TLS/SSL Renegotiation Abuse",
        "function": detect_tls_renegotiation,
        "enabled": True,
        "kwargs": {"renegotiation_threshold": 3},
        "description": "Detects repeated TLS ClientHello messages between hosts.",
    },
    {
        "id": "icmp_redirect",
        "name": "ICMP Redirect Attack",
        "function": detect_icmp_redirect_attack,
        "enabled": True,
        "kwargs": {"threshold": 5},
        "description": "Detects repeated ICMP Redirect messages and suspicious gateways.",
    },
    {
        "id": "icmp_tunneling",
        "name": "ICMP Tunneling / Anomaly",
        "function": detect_icmp_tunneling,
        "enabled": True,
        "kwargs": {"packet_threshold": 25, "avg_size_threshold": 120},
        "description": "Detects high-volume or large ICMP echo traffic that may indicate tunneling.",
    },
]


def _safe_stem(path):
    stem = Path(path).stem or "analysis"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._") or "analysis"


def create_run_paths(pcap_path, output_root=None):
    base_dir = Path(__file__).resolve().parent.parent
    output_root = Path(output_root) if output_root else base_dir / "output" / "runs"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{timestamp}_{_safe_stem(pcap_path)}"
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "events_path": str(run_dir / "events.jsonl"),
        "alerts_path": str(run_dir / "alerts.jsonl"),
    }


def selected_detectors(enabled_detectors=None, detector_overrides=None):
    enabled_set = set(enabled_detectors) if enabled_detectors else None
    detector_overrides = detector_overrides or {}
    selected = []

    for detector in DETECTOR_REGISTRY:
        if not detector.get("enabled", True):
            continue

        if enabled_set is not None and detector["id"] not in enabled_set:
            continue

        config = dict(detector)
        config["kwargs"] = dict(detector.get("kwargs", {}))
        config["kwargs"].update(detector_overrides.get(detector["id"], {}))
        selected.append(config)

    return selected


def run_parser(pcap_path, events_path):
    base_dir = Path(__file__).resolve().parent.parent
    parser_script = base_dir / "parser" / "pcap_parser.py"

    process = subprocess.run(
        [sys.executable, str(parser_script), pcap_path, events_path],
        capture_output=True,
        text=True,
    )

    return {
        "ok": process.returncode == 0,
        "stdout": process.stdout.strip(),
        "stderr": process.stderr.strip(),
        "returncode": process.returncode,
    }


def load_jsonl(path):
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def calculate_event_stats(events_path):
    packet_count = 0
    protocol_counts = Counter()
    top_sources = Counter()
    top_destinations = Counter()

    if not os.path.exists(events_path):
        return {
            "packet_count": 0,
            "protocol_counts": {},
            "top_sources": [],
            "top_destinations": [],
        }

    for event in load_jsonl(events_path):
        packet_count += 1
        protocol = event.get("transport") or event.get("layer") or event.get("highest_layer") or "UNKNOWN"
        protocol_counts[str(protocol)] += 1

        if event.get("src_ip"):
            top_sources[event["src_ip"]] += 1
        if event.get("dst_ip"):
            top_destinations[event["dst_ip"]] += 1

    return {
        "packet_count": packet_count,
        "protocol_counts": dict(protocol_counts),
        "top_sources": top_sources.most_common(10),
        "top_destinations": top_destinations.most_common(10),
    }


def save_alerts(alerts, alerts_path):
    with open(alerts_path, "w", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert, ensure_ascii=False) + "\n")


def run_pipeline(pcap_path, enabled_detectors=None, detector_overrides=None, output_root=None):
    paths = create_run_paths(pcap_path, output_root=output_root)
    errors = []
    detector_results = []

    logging.info("Starting pipeline for %s", pcap_path)
    parser_result = run_parser(pcap_path, paths["events_path"])

    if not parser_result["ok"]:
        errors.append({
            "stage": "parser",
            "message": "Parser execution failed",
            "details": parser_result["stderr"] or parser_result["stdout"],
        })
        return {
            "success": False,
            "run_id": paths["run_id"],
            "run_dir": paths["run_dir"],
            "events_path": paths["events_path"],
            "alerts_path": paths["alerts_path"],
            "packet_count": 0,
            "stats": calculate_event_stats(paths["events_path"]),
            "alerts": [],
            "detectors": detector_results,
            "errors": errors,
        }

    all_alerts = []
    for detector in selected_detectors(enabled_detectors, detector_overrides):
        try:
            alerts = detector["function"](paths["events_path"], **detector["kwargs"])
            all_alerts.extend(alerts)
            detector_results.append({
                "id": detector["id"],
                "name": detector["name"],
                "alert_count": len(alerts),
                "status": "ok",
                "kwargs": detector["kwargs"],
            })
        except Exception as error:
            logging.warning("%s detection failed: %s", detector["name"], error)
            errors.append({
                "stage": "detector",
                "detector": detector["name"],
                "message": str(error),
            })
            detector_results.append({
                "id": detector["id"],
                "name": detector["name"],
                "alert_count": 0,
                "status": "failed",
                "kwargs": detector["kwargs"],
            })

    try:
        enriched_alerts = enrich_alerts_with_virustotal(all_alerts)
    except Exception as error:
        logging.warning("Enrichment failed: %s", error)
        errors.append({
            "stage": "enrichment",
            "message": str(error),
        })
        enriched_alerts = all_alerts

    save_alerts(enriched_alerts, paths["alerts_path"])
    stats = calculate_event_stats(paths["events_path"])

    logging.info("Pipeline completed with %s alerts", len(enriched_alerts))

    return {
        "success": True,
        "run_id": paths["run_id"],
        "run_dir": paths["run_dir"],
        "events_path": paths["events_path"],
        "alerts_path": paths["alerts_path"],
        "packet_count": stats["packet_count"],
        "stats": stats,
        "alerts": enriched_alerts,
        "detectors": detector_results,
        "errors": errors,
    }


def count_packets(events_path):
    return calculate_event_stats(events_path)["packet_count"]
