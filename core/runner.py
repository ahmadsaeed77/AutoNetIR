import json
import logging
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from detection.hybrid.detector import build_detection_summary, detect_hybrid_attacks
from detection.hybrid.registry import ATTACK_REGISTRY
from enrichment.virustotal_lookup import enrich_alerts_with_virustotal

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


DETECTOR_REGISTRY = [
    {
        "id": "hybrid_known_attacks",
        "name": "Hybrid Known Attack Detection",
        "function": detect_hybrid_attacks,
        "enabled": True,
        "kwargs": {},
        "description": "Detects five known attacks using signature and behavior evidence.",
    }
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


def calculate_detection_summary(events_path):
    if not os.path.exists(events_path):
        return {
            "baseline_method": "per-PCAP peer baseline",
            "host_profiles": [],
            "pair_profiles": [],
            "arp_identity": {},
        }
    return build_detection_summary(events_path)


def save_alerts(alerts, alerts_path):
    with open(alerts_path, "w", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert, ensure_ascii=False) + "\n")


def run_pipeline(pcap_path, output_root=None):
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
            "detection_summary": calculate_detection_summary(paths["events_path"]),
            "alerts": [],
            "detectors": detector_results,
            "errors": errors,
        }

    try:
        alerts = detect_hybrid_attacks(paths["events_path"])
        detector_results.append({
            "id": "hybrid_known_attacks",
            "name": "Hybrid Known Attack Detection",
            "alert_count": len(alerts),
            "status": "ok",
            "supported_attacks": [attack["id"] for attack in ATTACK_REGISTRY],
        })
    except Exception as error:
        logging.warning("Hybrid detection failed: %s", error)
        errors.append({
            "stage": "detector",
            "detector": "Hybrid Known Attack Detection",
            "message": str(error),
        })
        alerts = []

    try:
        enriched_alerts = enrich_alerts_with_virustotal(alerts)
    except Exception as error:
        logging.warning("Enrichment failed: %s", error)
        errors.append({
            "stage": "enrichment",
            "message": str(error),
        })
        enriched_alerts = alerts

    save_alerts(enriched_alerts, paths["alerts_path"])
    stats = calculate_event_stats(paths["events_path"])
    detection_summary = calculate_detection_summary(paths["events_path"])

    logging.info("Pipeline completed with %s alerts", len(enriched_alerts))

    return {
        "success": True,
        "run_id": paths["run_id"],
        "run_dir": paths["run_dir"],
        "events_path": paths["events_path"],
        "alerts_path": paths["alerts_path"],
        "packet_count": stats["packet_count"],
        "stats": stats,
        "detection_summary": detection_summary,
        "alerts": enriched_alerts,
        "detectors": detector_results,
        "errors": errors,
    }


def count_packets(events_path):
    return calculate_event_stats(events_path)["packet_count"]
