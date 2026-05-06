import json
from collections import defaultdict

from detection.behavior.scoring import mean, safe_ratio
from detection.time_windows import DEFAULT_WINDOW_SECONDS, window_bucket, window_evidence
from utils.tcp_utils import has_tcp_flag

TCP_SYN_FLAG = 0x02
TCP_ACK_FLAG = 0x10
ICMP_ECHO_TYPES = {"0", "8"}
LOGIN_PATH_KEYWORDS = (
    "/login",
    "/admin",
    "/wp-login",
    "/signin",
    "/auth",
    "/account/login",
)


def load_events(events_path):
    with open(events_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def is_syn_without_ack(event):
    flags = event.get("tcp_flags")
    return has_tcp_flag(flags, TCP_SYN_FLAG) and not has_tcp_flag(flags, TCP_ACK_FLAG)


def is_icmp_echo(event):
    return event.get("transport") == "ICMP" and str(event.get("icmp_type")) in ICMP_ECHO_TYPES


def is_login_request(event):
    method = str(event.get("http_method") or "").upper()
    uri = str(event.get("http_uri") or "").lower()
    return method == "POST" and any(keyword in uri for keyword in LOGIN_PATH_KEYWORDS)


def _empty_host():
    return {
        "packet_count": 0,
        "destinations": set(),
        "syn_no_ack": 0,
        "syn_dst_ports_windows": defaultdict(set),
        "ssh_attempts": 0,
        "ssh_attempt_windows": defaultdict(int),
        "http_requests": 0,
        "http_login_attempts": 0,
        "http_login_attempt_windows": defaultdict(int),
        "http_login_responses": defaultdict(int),
        "icmp_echo": 0,
        "dst_ports": set(),
        "syn_dst_ports": set(),
        "arp_mac_addresses": set(),
    }


def build_features(events_path):
    hosts = defaultdict(_empty_host)
    pairs = defaultdict(lambda: {
        "src_ip": None,
        "dst_ip": None,
        "packet_count": 0,
        "syn_no_ack": 0,
        "syn_no_ack_windows": defaultdict(int),
        "syn_dst_ports": set(),
        "ssh_attempts": 0,
        "icmp_echo": 0,
        "icmp_echo_windows": defaultdict(int),
        "http_requests": 0,
        "http_login_attempts": 0,
        "frame_lengths": [],
    })
    arp_identity = defaultdict(set)

    for event in load_events(events_path):
        if event.get("layer") == "ARP":
            arp_ip = event.get("arp_src_ip")
            arp_mac = event.get("arp_src_mac")
            if arp_ip and arp_mac:
                arp_identity[arp_ip].add(arp_mac)
                hosts[arp_ip]["arp_mac_addresses"].add(arp_mac)
            continue

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        if not src_ip:
            continue

        host = hosts[src_ip]
        host["packet_count"] += 1
        if dst_ip:
            host["destinations"].add(dst_ip)

        pair_key = (src_ip, dst_ip or "")
        pair = pairs[pair_key]
        pair["src_ip"] = src_ip
        pair["dst_ip"] = dst_ip
        pair["packet_count"] += 1

        frame_len = event.get("frame_len") or event.get("ip_len")
        try:
            pair["frame_lengths"].append(int(frame_len))
        except (TypeError, ValueError):
            pass

        if event.get("transport") in {"TCP", "UDP"}:
            dst_port = event.get("dst_port")
            if dst_port:
                host["dst_ports"].add(dst_port)

        if event.get("transport") == "TCP" and is_syn_without_ack(event):
            bucket = window_bucket(event)
            host["syn_no_ack"] += 1
            pair["syn_no_ack"] += 1
            pair["syn_no_ack_windows"][bucket] += 1

            dst_port = event.get("dst_port")
            if dst_port:
                host["syn_dst_ports"].add(dst_port)
                pair["syn_dst_ports"].add(dst_port)
                host["syn_dst_ports_windows"][bucket].add(dst_port)

            if event.get("dst_port") == 22:
                host["ssh_attempts"] += 1
                host["ssh_attempt_windows"][bucket] += 1
                pair["ssh_attempts"] += 1

        if event.get("app_protocol") == "HTTP" or event.get("http_method"):
            host["http_requests"] += 1
            pair["http_requests"] += 1

            if is_login_request(event):
                bucket = window_bucket(event)
                host["http_login_attempts"] += 1
                host["http_login_attempt_windows"][bucket] += 1
                pair["http_login_attempts"] += 1
                response_code = event.get("http_response_code")
                if response_code:
                    host["http_login_responses"][str(response_code)] += 1

        if is_icmp_echo(event):
            bucket = window_bucket(event)
            host["icmp_echo"] += 1
            pair["icmp_echo"] += 1
            pair["icmp_echo_windows"][bucket] += 1

    host_profiles = []
    for src_ip, host in hosts.items():
        ssh_count, ssh_bucket = _max_count_window(host["ssh_attempt_windows"])
        login_count, login_bucket = _max_count_window(host["http_login_attempt_windows"])
        port_count, port_bucket = _max_set_window(host["syn_dst_ports_windows"])
        host_profiles.append({
            "src_ip": src_ip,
            "packet_count": host["packet_count"],
            "unique_destinations": len(host["destinations"]),
            "unique_dst_ports": len(host["dst_ports"]),
            "unique_syn_dst_ports": len(host["syn_dst_ports"]),
            "max_unique_syn_dst_ports_per_window": port_count,
            "port_scan_window": window_evidence(port_bucket, DEFAULT_WINDOW_SECONDS),
            "syn_no_ack": host["syn_no_ack"],
            "ssh_attempts": host["ssh_attempts"],
            "max_ssh_attempts_per_window": ssh_count,
            "ssh_attempts_window": window_evidence(ssh_bucket, DEFAULT_WINDOW_SECONDS),
            "http_requests": host["http_requests"],
            "http_login_attempts": host["http_login_attempts"],
            "max_http_login_attempts_per_window": login_count,
            "http_login_window": window_evidence(login_bucket, DEFAULT_WINDOW_SECONDS),
            "http_login_responses": dict(host["http_login_responses"]),
            "icmp_echo": host["icmp_echo"],
            "arp_mac_count": len(host["arp_mac_addresses"]),
            "arp_mac_addresses": sorted(host["arp_mac_addresses"]),
        })

    pair_profiles = []
    for pair in pairs.values():
        syn_count, syn_bucket = _max_count_window(pair["syn_no_ack_windows"])
        icmp_count, icmp_bucket = _max_count_window(pair["icmp_echo_windows"])
        pair_profiles.append({
            "src_ip": pair["src_ip"],
            "dst_ip": pair["dst_ip"],
            "packet_count": pair["packet_count"],
            "syn_no_ack": pair["syn_no_ack"],
            "max_syn_no_ack_per_window": syn_count,
            "syn_no_ack_window": window_evidence(syn_bucket, DEFAULT_WINDOW_SECONDS),
            "unique_syn_dst_ports": len(pair["syn_dst_ports"]),
            "ssh_attempts": pair["ssh_attempts"],
            "icmp_echo": pair["icmp_echo"],
            "max_icmp_echo_per_window": icmp_count,
            "icmp_echo_window": window_evidence(icmp_bucket, DEFAULT_WINDOW_SECONDS),
            "http_requests": pair["http_requests"],
            "http_login_attempts": pair["http_login_attempts"],
            "avg_frame_len": mean(pair["frame_lengths"]),
            "syn_ratio": safe_ratio(pair["syn_no_ack"], pair["packet_count"]),
        })

    host_profiles.sort(key=lambda row: row["packet_count"], reverse=True)
    pair_profiles.sort(key=lambda row: row["packet_count"], reverse=True)

    return {
        "host_profiles": host_profiles,
        "pair_profiles": pair_profiles,
        "arp_identity": {ip: sorted(macs) for ip, macs in arp_identity.items()},
        "baseline_method": "per-PCAP peer baseline",
    }


def _max_count_window(windows):
    if not windows:
        return 0, None
    return max(((count, bucket) for bucket, count in windows.items()), key=lambda item: item[0])


def _max_set_window(windows):
    if not windows:
        return 0, None
    return max(((len(values), bucket) for bucket, values in windows.items()), key=lambda item: item[0])
