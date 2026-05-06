import json


def write_events(tmp_path, events):
    path = tmp_path / "events.jsonl"
    with open(path, "w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")
    return str(path)


def tcp_syn(src_ip, dst_ip, dst_port, timestamp=None):
    event = {
        "layer": "IP",
        "transport": "TCP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 40000,
        "dst_port": dst_port,
        "tcp_flags": "0x0002",
    }
    if timestamp is not None:
        event["timestamp"] = timestamp
    return event


def tcp_syn_ack(src_ip, dst_ip, src_port, dst_port, timestamp=None):
    event = {
        "layer": "IP",
        "transport": "TCP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags_syn": 1,
        "tcp_flags_ack": 1,
    }
    if timestamp is not None:
        event["timestamp"] = timestamp
    return event


def http_get(src_ip, dst_ip, timestamp=None):
    return {
        "layer": "IP",
        "transport": "TCP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 40000,
        "dst_port": 80,
        "app_protocol": "HTTP",
        "http_method": "GET",
        "http_uri": "/",
        **({"timestamp": timestamp} if timestamp is not None else {}),
    }


def http_login_post(src_ip, dst_ip, timestamp=None):
    return {
        "layer": "IP",
        "transport": "TCP",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 40000,
        "dst_port": 80,
        "app_protocol": "HTTP",
        "http_method": "POST",
        "http_uri": "/login",
        "http_response_code": "401",
        **({"timestamp": timestamp} if timestamp is not None else {}),
    }
