import logging
import os
import time

import requests

from utils.ip_utils import is_public_ip

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"

LAST_REQUEST_TIME = 0
RATE_LIMIT_DELAY = 16


def rate_limited_request():
    global LAST_REQUEST_TIME
    now = time.time()

    if now - LAST_REQUEST_TIME < RATE_LIMIT_DELAY:
        sleep_time = RATE_LIMIT_DELAY - (now - LAST_REQUEST_TIME)
        time.sleep(sleep_time)

    LAST_REQUEST_TIME = time.time()


def lookup_ip_virustotal(ip):
    if not ip:
        return {"message": "No IP provided"}

    if not is_public_ip(ip):
        return {"message": "Skipped private IP"}

    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    url = f"{VT_BASE_URL}/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        rate_limited_request()

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return {"error": f"API status {response.status_code}"}

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
        }

        if result["malicious"] > 0:
            result["threat_level"] = "HIGH"
        elif result["suspicious"] > 0:
            result["threat_level"] = "MEDIUM"
        else:
            result["threat_level"] = "LOW"

        return result

    except Exception as e:
        logging.warning(f"VT lookup failed for {ip}: {e}")
        return {"error": str(e)}


def enrich_alerts_with_virustotal(alerts):
    cache = {}

    for alert in alerts:
        ip = alert.get("src_ip")

        if not ip:
            alert["virustotal"] = {"message": "No IP"}
            continue

        if ip in cache:
            alert["virustotal"] = cache[ip]
            continue

        vt_data = lookup_ip_virustotal(ip)
        cache[ip] = vt_data
        alert["virustotal"] = vt_data

    return alerts
