from parser.pcap_parser import detect_app_protocol, parse_packet


class Obj:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_parse_tcp_http_fields():
    packet = Obj(
        sniff_time="2026-01-01 00:00:00",
        highest_layer="HTTP",
        frame_info=Obj(len="120"),
        ip=Obj(src="10.0.0.5", dst="10.0.0.10", len="106"),
        tcp=Obj(
            srcport="51515",
            dstport="80",
            flags="0x0018",
            flags_syn="False",
            flags_ack="True",
            flags_reset="False",
            flags_fin="False",
        ),
        http=Obj(
            request_method="POST",
            request_uri="/login",
            host="example.local",
            response_code="401",
            user_agent="pytest-agent",
        ),
    )

    event = parse_packet(packet)

    assert event["transport"] == "TCP"
    assert event["app_protocol"] == "HTTP"
    assert event["http_method"] == "POST"
    assert event["http_uri"] == "/login"
    assert event["http_response_code"] == "401"


def test_parse_arp_fields():
    packet = Obj(
        sniff_time="2026-01-01 00:00:00",
        highest_layer="ARP",
        frame_info=Obj(len="60"),
        arp=Obj(
            src_proto_ipv4="192.168.1.1",
            dst_proto_ipv4="192.168.1.50",
            src_hw_mac="aa:aa:aa:aa:aa:aa",
            dst_hw_mac="ff:ff:ff:ff:ff:ff",
            opcode="2",
        ),
    )

    event = parse_packet(packet)

    assert event["layer"] == "ARP"
    assert event["arp_src_ip"] == "192.168.1.1"
    assert event["arp_src_mac"] == "aa:aa:aa:aa:aa:aa"


def test_parse_icmp_fields():
    packet = Obj(
        sniff_time="2026-01-01 00:00:00",
        highest_layer="ICMP",
        frame_info=Obj(len="98"),
        ip=Obj(src="10.0.0.2", dst="10.0.0.3", len="84"),
        icmp=Obj(type="8", code="0", ident="1", seq="10"),
    )

    event = parse_packet(packet)

    assert event["transport"] == "ICMP"
    assert event["icmp_type"] == "8"
    assert event["icmp_seq"] == "10"


def test_detect_app_protocol_common_ports_and_destination_priority():
    assert detect_app_protocol(51515, 3389) == "RDP"
    assert detect_app_protocol(51515, 3306) == "MYSQL"
    assert detect_app_protocol(22, 443) == "HTTPS"
    assert detect_app_protocol(5432, 65000) == "POSTGRESQL"
    assert detect_app_protocol(65000, 65001) is None
