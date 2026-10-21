"""
Unit and integration tests for report generation (CSV, JSON, PDF).
"""
import os
import csv
import json
import pytest
from reports.generator import export_events_csv, export_events_json, generate_pdf_report


@pytest.fixture
def sample_event_dicts():
    """Provides a list of sample event dictionaries with metadata."""
    return [
        {
            "id": 1,
            "dataset_id": 1,
            "timestamp": "2024-10-15T08:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "event_type": "http_request",
            "event_category": "Web Traffic",
            "hostname": "web-srv",
            "log_source": "zeek_http",
            "description": "GET /index.html",
            "severity": "low",
            "_epoch": 1728979200.0,
            "_internal": "hidden_value"
        },
        {
            "id": 2,
            "dataset_id": 1,
            "timestamp": "2024-10-15T08:05:00Z",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.3",
            "src_port": 54321,
            "dst_port": 22,
            "protocol": "TCP",
            "event_type": "ssh_login",
            "event_category": "Authentication",
            "hostname": "db-srv",
            "log_source": "auth_log",
            "description": "Failed root login attempt",
            "severity": "high",
            "_epoch": 1728979500.0
        }
    ]


def test_export_events_csv(test_temp_dir, sample_event_dicts):
    csv_path = os.path.join(test_temp_dir, "exported_events.csv")
    result_path = export_events_csv(sample_event_dicts, csv_path)

    assert os.path.exists(result_path)
    assert result_path == csv_path

    with open(result_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == len(sample_event_dicts)
    assert rows[0]["src_ip"] == "10.0.0.1"
    assert rows[0]["dst_ip"] == "10.0.0.2"
    assert rows[0]["dst_port"] == "80"
    # Internal keys should not be present
    assert "_internal" not in rows[0]
    assert "_epoch" not in rows[0]


def test_export_events_csv_empty(test_temp_dir):
    csv_path = os.path.join(test_temp_dir, "empty_events.csv")
    result_path = export_events_csv([], csv_path)

    assert os.path.exists(result_path)
    with open(result_path, mode="r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)

    assert "src_ip" in header
    assert "timestamp" in header
    assert "event_type" in header


def test_export_events_json(test_temp_dir, sample_event_dicts):
    json_path = os.path.join(test_temp_dir, "exported_events.json")
    result_path = export_events_json(sample_event_dicts, json_path)

    assert os.path.exists(result_path)
    with open(result_path, mode="r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, list)
    assert len(data) == len(sample_event_dicts)
    assert data[0]["src_ip"] == "10.0.0.1"
    assert "_internal" not in data[0]


def test_export_events_json_empty(test_temp_dir):
    json_path = os.path.join(test_temp_dir, "empty_events.json")
    result_path = export_events_json([], json_path)

    assert os.path.exists(result_path)
    with open(result_path, mode="r", encoding="utf-8") as f:
        data = json.load(f)

    assert data == []


def test_generate_pdf_report_basic(test_temp_dir):
    pdf_path = os.path.join(test_temp_dir, "basic_report.pdf")
    report_data = {
        "investigation": {
            "title": "Minimal Incident Report",
            "description": "Verification of basic PDF rendering",
            "status": "In Progress"
        },
        "stats": {
            "total_events": 25,
            "unique_hosts": 4,
            "alerts_count": 2
        }
    }

    result_path = generate_pdf_report(report_data, pdf_path)

    assert os.path.exists(result_path)
    assert os.path.getsize(result_path) > 0

    with open(result_path, "rb") as f:
        header = f.read(4)
    assert header == b"%PDF"


def test_generate_pdf_report_comprehensive(test_temp_dir, sample_event_dicts):
    pdf_path = os.path.join(test_temp_dir, "full_incident_report.pdf")
    report_data = {
        "dataset_name": "Campus Core Incident 2026-A",
        "investigation": {
            "title": "Campus Core Breach Investigation",
            "description": "Multi-stage intrusion targeting Student Records and Admin DB.",
            "status": "Closed",
            "time_range_start": "2026-03-01T08:00:00Z",
            "time_range_end": "2026-03-01T12:00:00Z",
            "analyst_notes": "Immediate mitigation completed. Subnet 10.0.0.0/24 isolated.",
            "findings": "Attacker gained foothold via unauthenticated HTTP endpoint."
        },
        "stats": {
            "total_events": len(sample_event_dicts),
            "unique_hosts": 3,
            "alerts_count": 2
        },
        "alerts": [
            {
                "rule_name": "Port Scanning Activity",
                "severity": "high",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "reason": "Sequential scan of 15 ports detected within 60s"
            },
            {
                "rule_name": "Suspicious DNS Resolution",
                "severity": "critical",
                "src_ip": "10.0.0.2",
                "dst_ip": "8.8.8.8",
                "reason": "Lookup to known C2 domain malware-c2.org"
            }
        ],
        "events": sample_event_dicts,
        "hosts": [
            {"ip_address": "10.0.0.1", "hostname": "workstation-lab-01", "event_count": 12, "first_seen": "2026-03-01 08:00:00", "last_seen": "2026-03-01 08:30:00"},
            {"ip_address": "10.0.0.2", "hostname": "srv-db-admin", "event_count": 8, "first_seen": "2026-03-01 08:00:00", "last_seen": "2026-03-01 08:25:00"},
            {"ip_address": "10.0.0.3", "hostname": "srv-web-gateway", "event_count": 5, "first_seen": "2026-03-01 08:05:00", "last_seen": "2026-03-01 08:20:00"}
        ]
    }

    result_path = generate_pdf_report(report_data, pdf_path)

    assert os.path.exists(result_path)
    file_size = os.path.getsize(result_path)
    assert file_size > 1000  # Non-trivial PDF output

    with open(result_path, "rb") as f:
        header = f.read(4)
    assert header == b"%PDF"


def test_generate_pdf_report_empty_data(test_temp_dir):
    pdf_path = os.path.join(test_temp_dir, "empty_report.pdf")
    result_path = generate_pdf_report({}, pdf_path)

    assert os.path.exists(result_path)
    assert os.path.getsize(result_path) > 0
