import os
import json
import sys
import asyncio
import shutil
import pyshark


def first_available(layer, *names):
    for name in names:
        value = getattr(layer, name, None)
        if value is not None:
            return value
    return None


def get_tshark_path():
    """
    Find tshark automatically on different devices.

    Priority:
    1. TSHARK_PATH environment variable
    2. System PATH
    3. Common installation paths
    """

    env_path = os.getenv("TSHARK_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    system_path = shutil.which("tshark")
    if system_path:
        return system_path

    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark",
    ]

    for path in common_paths:
        if os.path.exists(path):
            return path

    raise FileNotFoundError(
        "tshark was not found. Please install Wireshark/TShark "
        "or set TSHARK_PATH environment variable."
    )


def detect_app_protocol(src_port, dst_port):
    ports = {src_port, dst_port}

    port_map = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
    }

    for port, protocol in port_map.items():
        if port in ports:
            return protocol

    return None


def parse_packet(pkt):
    frame_len = None
    try:
        frame_len = int(getattr(getattr(pkt, "frame_info", None), "len", 0))
    except (TypeError, ValueError):
        frame_len = None

    event = {
        "time": str(getattr(pkt, "sniff_time", "")),
        "highest_layer": getattr(pkt, "highest_layer", None),
        "frame_len": frame_len,
    }

    # ARP packets
    if hasattr(pkt, "arp"):
        event["layer"] = "ARP"
        event["arp_src_ip"] = getattr(pkt.arp, "src_proto_ipv4", None)
        event["arp_dst_ip"] = getattr(pkt.arp, "dst_proto_ipv4", None)
        event["arp_src_mac"] = getattr(pkt.arp, "src_hw_mac", None)
        event["arp_dst_mac"] = getattr(pkt.arp, "dst_hw_mac", None)
        event["arp_opcode"] = getattr(pkt.arp, "opcode", None)
        return event

    # IP packets
    if hasattr(pkt, "ip"):
        event["layer"] = "IP"
        event["src_ip"] = getattr(pkt.ip, "src", None)
        event["dst_ip"] = getattr(pkt.ip, "dst", None)
        try:
            event["ip_len"] = int(getattr(pkt.ip, "len", 0))
        except (TypeError, ValueError):
            event["ip_len"] = None

        if hasattr(pkt, "tcp"):
            event["transport"] = "TCP"

            try:
                event["src_port"] = int(getattr(pkt.tcp, "srcport", 0))
                event["dst_port"] = int(getattr(pkt.tcp, "dstport", 0))
            except (ValueError, TypeError):
                event["src_port"] = 0
                event["dst_port"] = 0

            event["app_protocol"] = detect_app_protocol(
                event["src_port"],
                event["dst_port"]
            )

            event["tcp_flags"] = getattr(pkt.tcp, "flags", None)
            event["tcp_flags_syn"] = getattr(pkt.tcp, "flags_syn", None)
            event["tcp_flags_ack"] = getattr(pkt.tcp, "flags_ack", None)
            event["tcp_flags_rst"] = getattr(pkt.tcp, "flags_reset", None)
            event["tcp_flags_fin"] = getattr(pkt.tcp, "flags_fin", None)

            if hasattr(pkt, "http"):
                event["app_protocol"] = "HTTP"
                event["http_method"] = first_available(pkt.http, "request_method")
                event["http_uri"] = first_available(
                    pkt.http,
                    "request_full_uri",
                    "request_uri",
                    "request_uri_path",
                )
                event["http_host"] = first_available(pkt.http, "host")
                event["http_response_code"] = first_available(
                    pkt.http,
                    "response_code",
                    "response_code_desc",
                )
                event["http_user_agent"] = first_available(pkt.http, "user_agent")

            if hasattr(pkt, "tls"):
                event["app_protocol"] = "HTTPS"
                event["tls_handshake_type"] = getattr(pkt.tls, "handshake_type", None)
                event["tls_record_content_type"] = getattr(pkt.tls, "record_content_type", None)

            elif hasattr(pkt, "ssl"):
                event["app_protocol"] = "HTTPS"
                event["tls_handshake_type"] = getattr(pkt.ssl, "handshake_type", None)
                event["tls_record_content_type"] = getattr(pkt.ssl, "record_content_type", None)

        elif hasattr(pkt, "udp"):
            event["transport"] = "UDP"

            try:
                event["src_port"] = int(getattr(pkt.udp, "srcport", 0))
                event["dst_port"] = int(getattr(pkt.udp, "dstport", 0))
            except (ValueError, TypeError):
                event["src_port"] = 0
                event["dst_port"] = 0

            event["app_protocol"] = detect_app_protocol(
                event["src_port"],
                event["dst_port"]
            )

        elif hasattr(pkt, "icmp"):
            event["transport"] = "ICMP"
            event["icmp_type"] = getattr(pkt.icmp, "type", None)
            event["icmp_code"] = getattr(pkt.icmp, "code", None)
            event["icmp_id"] = getattr(pkt.icmp, "ident", None)
            event["icmp_seq"] = getattr(pkt.icmp, "seq", None)
            event["icmp_gateway"] = (
                getattr(pkt.icmp, "redir_gw", None)
                or getattr(pkt.icmp, "gateway", None)
                or getattr(pkt.icmp, "addr", None)
            )

        else:
            event["transport"] = None

        return event

    # Other packet types
    event["layer"] = "OTHER"
    return event


def parse_pcap_file(pcap_path, output_path):
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cap = pyshark.FileCapture(
        pcap_path,
        tshark_path=get_tshark_path(),
        eventloop=loop
    )

    count = 0

    try:
        with open(output_path, "w", encoding="utf-8") as file:
            for pkt in cap:
                try:
                    event = parse_packet(pkt)
                    file.write(json.dumps(event) + "\n")
                    count += 1
                except Exception as error:
                    print(f"[!] Error parsing packet #{count + 1}: {error}")

    finally:
        cap.close()
        loop.close()

    return count


def main():
    if len(sys.argv) != 3:
        print("Usage: python pcap_parser.py <input_pcap> <output_jsonl>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2]

    try:
        count = parse_pcap_file(pcap_path, output_path)
        print(f"Done. Parsed {count} packets into {output_path}")

    except Exception as error:
        print(f"Parser failed: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
