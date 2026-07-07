import pytest

from netscanner.validation import parse_ports, ports_to_nmap, validate_target


def test_parse_ports_supports_lists_and_ranges():
    assert parse_ports("443,22,80,8000-8002,80") == [22, 80, 443, 8000, 8001, 8002]
    assert ports_to_nmap([22, 80, 443]) == "22,80,443"


def test_parse_ports_rejects_invalid_values():
    with pytest.raises(ValueError):
        parse_ports("0,443")
    with pytest.raises(ValueError):
        parse_ports("80-70")
    with pytest.raises(ValueError):
        parse_ports("abc")


def test_validate_target_accepts_ip_cidr_and_hostname():
    assert validate_target("192.168.1.10") == "192.168.1.10"
    assert validate_target("192.168.1.0/30") == "192.168.1.0/30"
    assert validate_target("scan.lab.local") == "scan.lab.local"


def test_validate_target_rejects_multi_target_or_url():
    with pytest.raises(ValueError):
        validate_target("https://example.com")
    with pytest.raises(ValueError):
        validate_target("192.168.1.1,192.168.1.2")
