from enrichment import virustotal_lookup
from utils.ip_utils import is_public_ip
from utils.tcp_utils import has_tcp_flag


def test_has_tcp_flag():
    assert has_tcp_flag("0x0012", 0x02) is True
    assert has_tcp_flag("0x0012", 0x10) is True
    assert has_tcp_flag("0x0012", 0x04) is False
    assert has_tcp_flag(None, 0x02) is False
    assert has_tcp_flag("not-a-flag", 0x02) is False


def test_is_public_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("not-an-ip") is False


def test_virustotal_skips_private_ip(monkeypatch):
    monkeypatch.setattr(virustotal_lookup, "VT_API_KEY", "fake-key")

    result = virustotal_lookup.lookup_ip_virustotal("192.168.1.10")

    assert result == {"message": "Skipped private IP"}


def test_virustotal_missing_api_key(monkeypatch):
    monkeypatch.setattr(virustotal_lookup, "VT_API_KEY", None)

    result = virustotal_lookup.lookup_ip_virustotal("8.8.8.8")

    assert result == {"error": "VT_API_KEY not set"}


def test_virustotal_api_error(monkeypatch):
    class FakeResponse:
        status_code = 500

    monkeypatch.setattr(virustotal_lookup, "VT_API_KEY", "fake-key")
    monkeypatch.setattr(virustotal_lookup, "rate_limited_request", lambda: None)
    monkeypatch.setattr(virustotal_lookup.requests, "get", lambda *args, **kwargs: FakeResponse())

    result = virustotal_lookup.lookup_ip_virustotal("8.8.8.8")

    assert result == {"error": "API status 500"}
