from detection.behavior import arp_poisoning as arp_behavior
from detection.behavior import dos_attack as dos_behavior
from detection.behavior import http_login_bruteforce as http_behavior
from detection.behavior import port_scan as port_behavior
from detection.behavior import ssh_bruteforce as ssh_behavior
from detection.signatures import arp_poisoning as arp_signature
from detection.signatures import dos_attack as dos_signature
from detection.signatures import http_login_bruteforce as http_signature
from detection.signatures import port_scan as port_signature
from detection.signatures import ssh_bruteforce as ssh_signature


ATTACK_REGISTRY = [
    {
        "id": "ssh_bruteforce",
        "name": "SSH Brute Force-like Attempts",
        "signature": ssh_signature.detect,
        "behavior": ssh_behavior.detect,
        "recommendation": "Verify whether the source is authorized. Block or rate-limit repeated SSH attempts and review SSH logs on the target.",
        "limitations": "PCAP traffic cannot confirm SSH login success or failure because SSH authentication is encrypted.",
    },
    {
        "id": "http_login_bruteforce",
        "name": "HTTP Login Brute Force",
        "signature": http_signature.detect,
        "behavior": http_behavior.detect,
        "recommendation": "Review web authentication logs, rate-limit the source, and enable account lockout or MFA for exposed login pages.",
        "limitations": "Only unencrypted HTTP login paths are visible. HTTPS login content cannot be inspected from ordinary PCAP data.",
    },
    {
        "id": "port_scan",
        "name": "Port Scanning",
        "signature": port_signature.detect,
        "behavior": port_behavior.detect,
        "recommendation": "Confirm whether the source is an approved scanner. If not, block or isolate it and review exposed services.",
        "limitations": "Short captures may miss slow scans spread over a longer time window.",
    },
    {
        "id": "arp_poisoning",
        "name": "ARP Spoofing / Poisoning",
        "signature": arp_signature.detect,
        "behavior": arp_behavior.detect,
        "recommendation": "Verify legitimate MAC mappings, inspect switch ARP tables, and enable Dynamic ARP Inspection when available.",
        "limitations": "Legitimate MAC changes during failover can look similar and should be validated with network context.",
    },
    {
        "id": "dos_attack",
        "name": "DoS Attack",
        "signature": dos_signature.detect,
        "behavior": dos_behavior.detect,
        "recommendation": "Rate-limit or block the source, check service health, and review firewall or load balancer telemetry.",
        "limitations": "High-volume legitimate traffic can resemble DoS in small captures; validate with service logs.",
    },
]
