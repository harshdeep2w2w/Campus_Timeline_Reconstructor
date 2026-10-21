"""
Tests for parsers module: CSV, JSON, and Zeek logs.
"""
import os
import json
import tempfile
import pytest
from parsers.csv_parser import parse_csv
from parsers.json_parser import parse_json


def test_parse_valid_csv(tmp_path):
    """Test parsing a well-formed CSV file with standard columns."""
    csv_file = tmp_path / "valid.csv"
    csv_file.write_text(
        "timestamp,source_ip,dest_ip,source_port,dest_port,protocol,event_type,severity,description\n"
        "2024-10-15T08:00:00Z,10.0.1.15,10.0.2.10,50000,80,TCP,http,informational,Web traffic\n"
        "2024-10-15T08:01:00Z,10.0.1.20,10.0.2.1,50001,53,UDP,dns,informational,DNS request\n",
        encoding="utf-8"
    )

    records, errors = parse_csv(str(csv_file))
    assert len(errors) == 0
    assert len(records) == 2

    assert records[0]["src_ip"] == "10.0.1.15"
    assert records[0]["dst_ip"] == "10.0.2.10"
    assert records[0]["src_port"] == 50000
    assert records[0]["dst_port"] == 80
    assert records[0]["protocol"] == "TCP"
    assert records[0]["event_category"] == "HTTP"

    assert records[1]["src_ip"] == "10.0.1.20"
    assert records[1]["dst_port"] == 53
    assert records[1]["event_category"] == "DNS"


def test_parse_csv_with_alternate_columns(tmp_path):
    """Test parsing CSV with alternate column headers (e.g. src_ip, dst_ip, sport, dport, proto)."""
    csv_file = tmp_path / "alt_columns.csv"
    csv_file.write_text(
        "ts,src_ip,dst_ip,sport,dport,proto,action,level,msg\n"
        "2024-10-15 08:30:00,10.0.1.45,10.0.2.20,49152,25,tcp,smtp_mail,warning,Email transfer\n",
        encoding="utf-8"
    )

    records, errors = parse_csv(str(csv_file))
    assert len(errors) == 0
    assert len(records) == 1
    rec = records[0]
    assert rec["src_ip"] == "10.0.1.45"
    assert rec["dst_ip"] == "10.0.2.20"
    assert rec["src_port"] == 49152
    assert rec["dst_port"] == 25
    assert rec["protocol"] == "TCP"
    assert rec["severity"] == "medium"
    assert rec["description"] == "Email transfer"


def test_parse_csv_with_missing_columns(tmp_path):
    """Test parsing CSV with missing non-essential columns."""
    csv_file = tmp_path / "missing_cols.csv"
    csv_file.write_text(
        "timestamp,source_ip,dest_ip\n"
        "2024-10-15T09:00:00Z,10.0.1.10,10.0.2.10\n",
        encoding="utf-8"
    )

    records, errors = parse_csv(str(csv_file))
    assert len(records) == 1
    rec = records[0]
    assert rec["src_ip"] == "10.0.1.10"
    assert rec["dst_ip"] == "10.0.2.10"
    assert rec["protocol"] == "TCP"  # Defaults to TCP
    assert rec["src_port"] is None
    assert rec["dst_port"] is None


def test_parse_csv_with_invalid_data(tmp_path):
    """Test handling of bad IP placeholders and invalid ports."""
    csv_file = tmp_path / "invalid_data.csv"
    csv_file.write_text(
        "timestamp,src_ip,dst_ip,src_port,dst_port\n"
        "2024-10-15T09:30:00Z,-,null,invalid_port,99999\n",
        encoding="utf-8"
    )

    records, errors = parse_csv(str(csv_file))
    assert len(records) == 1
    rec = records[0]
    assert rec["src_ip"] is None
    assert rec["dst_ip"] is None
    assert rec["src_port"] is None
    assert rec["dst_port"] is None  # 99999 > 65535, so None


def test_parse_empty_csv(tmp_path):
    """Test parsing an empty CSV file or empty string."""
    empty_file = tmp_path / "empty.csv"
    empty_file.write_text("", encoding="utf-8")

    records, errors = parse_csv(str(empty_file))
    assert len(records) == 0
    assert len(errors) > 0


def test_parse_valid_json(tmp_path):
    """Test parsing a valid JSON array of event objects."""
    json_file = tmp_path / "valid.json"
    data = [
        {
            "timestamp": "2024-10-15T10:00:00Z",
            "src_ip": "10.0.1.30",
            "dst_ip": "10.0.2.10",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": "TCP",
            "event_type": "tls_connect",
            "severity": "informational"
        },
        {
            "timestamp": "2024-10-15T10:01:00Z",
            "src_ip": "10.0.1.31",
            "dst_ip": "10.0.2.10",
            "src_port": 50001,
            "dst_port": 80,
            "protocol": "TCP",
            "event_type": "http_get",
            "severity": "low"
        }
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")

    records, errors = parse_json(str(json_file))
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["src_ip"] == "10.0.1.30"
    assert records[0]["dst_port"] == 443
    assert records[0]["event_category"] == "TLS/HTTPS"


def test_parse_json_with_nested_fields(tmp_path):
    """Test parsing Zeek-style nested JSON objects (e.g. id.orig_h, id.resp_h)."""
    json_file = tmp_path / "nested.json"
    data = [
        {
            "ts": 1729000000.5,
            "id": {
                "orig_h": "10.0.1.45",
                "resp_h": "10.0.2.1",
                "orig_p": 54321,
                "resp_p": 53
            },
            "proto": "udp",
            "service": "dns",
            "query": "malware-c2.xyz"
        }
    ]
    json_file.write_text(json.dumps(data), encoding="utf-8")

    records, errors = parse_json(str(json_file))
    assert len(errors) == 0
    assert len(records) == 1
    rec = records[0]
    assert rec["src_ip"] == "10.0.1.45"
    assert rec["dst_ip"] == "10.0.2.1"
    assert rec["src_port"] == 54321
    assert rec["dst_port"] == 53
    assert rec["protocol"] == "UDP"
    assert rec["event_category"] == "DNS"


def test_parse_invalid_json(tmp_path):
    """Test handling of malformed JSON content."""
    json_file = tmp_path / "invalid.json"
    json_file.write_text("{ unquoted_key: 'broken value', }", encoding="utf-8")

    records, errors = parse_json(str(json_file))
    assert len(records) == 0
    assert len(errors) > 0


def test_parse_empty_json(tmp_path):
    """Test parsing an empty JSON array."""
    json_file = tmp_path / "empty.json"
    json_file.write_text("[]", encoding="utf-8")

    records, errors = parse_json(str(json_file))
    assert len(records) == 0
    assert len(errors) == 0
