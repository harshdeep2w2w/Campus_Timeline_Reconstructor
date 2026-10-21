"""
Tests for engine.normalizer module.
Verifies normalization of timestamps, IPs, ports, protocols, severities, and event categories.
"""
import pytest
import datetime
from engine.normalizer import (
    normalize_timestamp,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_severity,
    categorize_event,
    normalize_event,
)


def test_normalize_timestamp_iso():
    """Verify ISO format timestamp parses correctly."""
    ts = "2024-10-15T08:30:00"
    result = normalize_timestamp(ts)
    assert result is not None
    assert "2024-10-15" in result
    assert "08:30:00" in result


def test_normalize_timestamp_unix():
    """Verify integer and float unix timestamps convert to ISO."""
    # 1697358600 = 2023-10-15T08:30:00Z
    ts = 1697358600
    result = normalize_timestamp(ts)
    assert result is not None
    assert "2023-10-15" in result

    # Test millisecond unix timestamp
    ts_ms = 1697358600000
    result_ms = normalize_timestamp(ts_ms)
    assert "2023-10-15" in result_ms


def test_normalize_timestamp_common_formats():
    """Verify human readable date formats parse successfully."""
    ts1 = "Oct 15, 2024 08:30:00"
    res1 = normalize_timestamp(ts1)
    assert "2024-10-15" in res1

    ts2 = "2024/10/15 08:30:00"
    res2 = normalize_timestamp(ts2)
    assert "2024-10-15" in res2


def test_normalize_timestamp_invalid():
    """Verify bad strings or None return a fallback ISO timestamp."""
    bad_ts = "not-a-valid-timestamp-string-xyz"
    res = normalize_timestamp(bad_ts)
    assert res is not None
    # Must be valid ISO string format
    datetime.datetime.fromisoformat(res)

    res_none = normalize_timestamp(None)
    assert res_none is not None
    datetime.datetime.fromisoformat(res_none)


def test_normalize_ip_valid():
    """Verify standard IP addresses are stripped and preserved."""
    assert normalize_ip("10.0.1.15") == "10.0.1.15"
    assert normalize_ip("  192.168.1.1  ") == "192.168.1.1"
    assert normalize_ip("['10.0.2.10']") == "10.0.2.10"


def test_normalize_ip_invalid():
    """Verify invalid / null IP placeholders return None or cleaned string."""
    assert normalize_ip(None) is None
    assert normalize_ip("-") is None
    assert normalize_ip("null") is None
    assert normalize_ip("None") is None
    assert normalize_ip("NaN") is None
    assert normalize_ip("") is None
    # For arbitrary string, stripped string is returned gracefully without crash
    res = normalize_ip("not-an-ip")
    assert res == "not-an-ip"


def test_normalize_port():
    """Verify port string to int conversion, boundary validation, and error handling."""
    assert normalize_port("80") == 80
    assert normalize_port(443) == 443
    assert normalize_port("8080.0") == 8080
    assert normalize_port("abc") is None
    assert normalize_port(None) is None
    assert normalize_port("-") is None
    assert normalize_port(70000) is None  # Out of range
    assert normalize_port(-1) is None     # Negative


def test_normalize_protocol():
    """Verify protocol normalization to uppercase and numeric mapping."""
    assert normalize_protocol("tcp") == "TCP"
    assert normalize_protocol("Udp") == "UDP"
    assert normalize_protocol("icmp") == "ICMP"
    assert normalize_protocol(None) == "TCP"
    assert normalize_protocol("6") == "TCP"
    assert normalize_protocol("17") == "UDP"


def test_normalize_severity():
    """Verify severity level mapping to standard vocabulary."""
    assert normalize_severity("HIGH") == "high"
    assert normalize_severity("crit") == "critical"
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("med") == "medium"
    assert normalize_severity("warning") == "medium"
    assert normalize_severity("low") == "low"
    assert normalize_severity("unknown_level") == "informational"
    assert normalize_severity(None) == "informational"


def test_categorize_event_dns():
    """Verify destination port 53 maps to DNS."""
    event = {"dst_port": 53, "protocol": "UDP"}
    assert categorize_event(event) == "DNS"


def test_categorize_event_http():
    """Verify destination port 80 maps to HTTP."""
    event = {"dst_port": 80, "protocol": "TCP"}
    assert categorize_event(event) == "HTTP"


def test_categorize_event_by_type():
    """Verify event_type string takes precedence or categorizes correctly."""
    event1 = {"event_type": "dns_query"}
    assert categorize_event(event1) == "DNS"

    event2 = {"event_type": "ssh_login"}
    assert categorize_event(event2) == "SSH"

    event3 = {"event_type": "dhcp_ack"}
    assert categorize_event(event3) == "DHCP"


def test_normalize_event_full():
    """Verify complete event dictionary normalization."""
    raw = {
        "dataset_id": 1,
        "time": "2024-10-15 08:30:00",
        "source_ip": "10.0.1.45",
        "dest_ip": "10.0.2.10",
        "source_port": "54321",
        "dest_port": "80",
        "proto": "tcp",
        "service": "http",
        "host": "webserver.campus.edu",
        "msg": "HTTP GET /index.html",
        "level": "INFO"
    }
    normalized = normalize_event(raw)
    assert normalized["dataset_id"] == 1
    assert "2024-10-15" in normalized["timestamp"]
    assert normalized["src_ip"] == "10.0.1.45"
    assert normalized["dst_ip"] == "10.0.2.10"
    assert normalized["src_port"] == 54321
    assert normalized["dst_port"] == 80
    assert normalized["protocol"] == "TCP"
    assert normalized["event_category"] == "HTTP"
    assert normalized["hostname"] == "webserver.campus.edu"
    assert normalized["severity"] == "informational"
    assert normalized["normalized"] == 1
    assert "raw_data" in normalized
