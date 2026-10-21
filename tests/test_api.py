"""
Integration tests for Flask API endpoints (/api/*).
"""
import io
import json
import pytest
from database.db import insert_dataset, insert_event, insert_alert


def test_api_dashboard_stats(client, sample_dataset, sample_events):
    response = client.get(f"/api/dashboard/stats?dataset_id={sample_dataset}")
    assert response.status_code == 200
    data = response.get_json()
    assert "total_events" in data
    assert "unique_hosts" in data
    assert "alerts_by_severity" in data
    assert data["total_events"] >= 4


def test_api_dashboard_charts(client, sample_dataset, sample_events):
    # Activity over time
    resp_act = client.get(f"/api/dashboard/activity-over-time?dataset_id={sample_dataset}")
    assert resp_act.status_code == 200
    assert isinstance(resp_act.get_json(), list)

    # Top hosts
    resp_top = client.get(f"/api/dashboard/top-hosts?dataset_id={sample_dataset}&limit=5")
    assert resp_top.status_code == 200
    top_data = resp_top.get_json()
    assert "top_sources" in top_data
    assert "top_destinations" in top_data

    # Protocol distribution
    resp_proto = client.get(f"/api/dashboard/protocol-distribution?dataset_id={sample_dataset}")
    assert resp_proto.status_code == 200
    assert isinstance(resp_proto.get_json(), list)

    # Recent alerts
    resp_alerts = client.get(f"/api/dashboard/recent-alerts?dataset_id={sample_dataset}")
    assert resp_alerts.status_code == 200
    assert isinstance(resp_alerts.get_json(), list)


def test_api_upload_csv(client):
    csv_content = (
        "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,event_type,event_category,hostname,severity,description\n"
        "2024-10-15T09:00:00Z,192.168.1.100,192.168.1.200,44332,80,TCP,web_request,HTTP,web-srv,low,HTTP GET /\n"
        "2024-10-15T09:01:00Z,192.168.1.100,192.168.1.200,44334,22,TCP,ssh_probe,SSH,ssh-srv,medium,SSH Connect\n"
    )
    data = {
        'file': (io.BytesIO(csv_content.encode('utf-8')), 'test_upload.csv'),
        'dataset_name': 'API Test Dataset'
    }
    response = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 201
    res_json = response.get_json()
    assert res_json['success'] is True
    assert res_json['record_count'] == 2
    assert 'dataset_id' in res_json


def test_api_upload_no_file(client):
    response = client.post('/api/upload', data={}, content_type='multipart/form-data')
    assert response.status_code == 400
    assert response.get_json()['success'] is False


def test_api_upload_empty_filename(client):
    data = {
        'file': (io.BytesIO(b''), '')
    }
    response = client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 400
    assert response.get_json()['success'] is False


def test_api_timeline_events(client, sample_dataset, sample_events):
    # Unfiltered
    resp = client.get(f"/api/timeline/events?dataset_id={sample_dataset}&page=1&per_page=10")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "events" in data
    assert "total" in data
    assert data["total"] >= 4

    # Filtered by source IP
    resp_filtered = client.get(f"/api/timeline/events?dataset_id={sample_dataset}&src_ip=10.0.1.15")
    assert resp_filtered.status_code == 200
    data_filtered = resp_filtered.get_json()
    assert len(data_filtered["events"]) >= 1


def test_api_timeline_event_detail(client, sample_dataset, sample_events):
    event_id = sample_events[0]
    resp = client.get(f"/api/timeline/event/{event_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["id"] == event_id
    assert "related_events" in data

    # Non-existent event
    resp_404 = client.get("/api/timeline/event/999999")
    assert resp_404.status_code == 404


def test_api_correlation_endpoints(client, sample_dataset, sample_events):
    event_id = sample_events[0]

    # Related events
    resp_related = client.get(f"/api/correlation/related/{event_id}?time_window=600")
    assert resp_related.status_code == 200
    data_related = resp_related.get_json()
    assert "event" in data_related
    assert "related_events" in data_related

    # Correlated groups
    resp_groups = client.get(f"/api/correlation/groups?dataset_id={sample_dataset}&time_window=600")
    assert resp_groups.status_code == 200
    data_groups = resp_groups.get_json()
    assert isinstance(data_groups, list)


def test_api_network_graph(client, sample_dataset, sample_events):
    resp = client.get(f"/api/network/graph?dataset_id={sample_dataset}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0


def test_api_network_host_detail(client, sample_dataset, sample_events):
    resp = client.get(f"/api/network/host/10.0.1.15?dataset_id={sample_dataset}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ip"] == "10.0.1.15"
    assert "connections" in data


def test_api_alerts_lifecycle(app, client, sample_dataset, sample_events):
    # Insert test alert
    with app.app_context():
        alert_id = insert_alert({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T08:00:00Z',
            'alert_type': 'port_scan',
            'severity': 'high',
            'rule_name': 'Test Port Scan Alert',
            'reason': 'Multiple port attempts',
            'src_ip': '10.0.1.15',
            'dst_ip': '10.0.2.1',
            'event_ids': str(sample_events[0])
        })

    # List alerts
    resp = client.get(f"/api/alerts?dataset_id={sample_dataset}")
    assert resp.status_code == 200
    alerts_data = resp.get_json()
    assert "alerts" in alerts_data
    assert alerts_data["total"] >= 1

    # Single alert detail
    resp_detail = client.get(f"/api/alerts/{alert_id}")
    assert resp_detail.status_code == 200
    detail_data = resp_detail.get_json()
    assert detail_data["id"] == alert_id
    assert "associated_events" in detail_data

    # Update alert status
    patch_resp = client.patch(
        f"/api/alerts/{alert_id}",
        data=json.dumps({"status": "acknowledged"}),
        content_type="application/json"
    )
    assert patch_resp.status_code == 200
    assert patch_resp.get_json()["success"] is True


def test_api_investigations_crud(client, sample_dataset, sample_events):
    # 1. Create
    create_payload = {
        "dataset_id": sample_dataset,
        "title": "API Test Investigation Case",
        "description": "Investigating potential lateral movement",
        "status": "open",
        "analyst_notes": "Initiated automated triage."
    }
    create_resp = client.post(
        "/api/investigations",
        data=json.dumps(create_payload),
        content_type="application/json"
    )
    assert create_resp.status_code == 201
    inv_data = create_resp.get_json()
    assert inv_data["success"] is True
    inv_id = inv_data["id"]

    # 2. List
    list_resp = client.get("/api/investigations")
    assert list_resp.status_code == 200
    assert len(list_resp.get_json()) >= 1

    # 3. Detail
    detail_resp = client.get(f"/api/investigations/{inv_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.get_json()["title"] == "API Test Investigation Case"

    # 4. Pin events and hosts
    pin_ev_resp = client.post(
        f"/api/investigations/{inv_id}/events",
        data=json.dumps({"event_ids": [sample_events[0]]}),
        content_type="application/json"
    )
    assert pin_ev_resp.status_code == 200

    pin_host_resp = client.post(
        f"/api/investigations/{inv_id}/hosts",
        data=json.dumps({"host_ips": ["10.0.1.15"]}),
        content_type="application/json"
    )
    assert pin_host_resp.status_code == 200

    # 5. Update
    update_resp = client.put(
        f"/api/investigations/{inv_id}",
        data=json.dumps({"status": "closed", "findings": "Host contained."}),
        content_type="application/json"
    )
    assert update_resp.status_code == 200

    # 6. Unpin event
    unpin_resp = client.delete(f"/api/investigations/{inv_id}/events/{sample_events[0]}")
    assert unpin_resp.status_code == 200

    # 7. Delete investigation
    del_resp = client.delete(f"/api/investigations/{inv_id}")
    assert del_resp.status_code == 200


def test_api_datasets_lifecycle(client, sample_dataset):
    # Preview
    prev_resp = client.get(f"/api/datasets/{sample_dataset}/preview")
    assert prev_resp.status_code == 200
    assert "dataset" in prev_resp.get_json()

    # List datasets
    list_resp = client.get("/api/datasets")
    assert list_resp.status_code == 200
    assert len(list_resp.get_json()) >= 1

    # Delete dataset
    del_resp = client.delete(f"/api/datasets/{sample_dataset}")
    assert del_resp.status_code == 200


def test_api_datasets_load_sample(client):
    resp = client.post("/api/datasets/load-sample")
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["success"] is True
    assert "dataset_id" in data


def test_api_settings_get_and_put(client):
    get_resp = client.get("/api/settings")
    assert get_resp.status_code == 200
    data = get_resp.get_json()
    assert "settings" in data
    assert "rules" in data

    put_resp = client.put(
        "/api/settings",
        data=json.dumps({"port_scan_threshold": "15"}),
        content_type="application/json"
    )
    assert put_resp.status_code == 200


def test_api_reports_exports(client, sample_dataset, sample_events):
    # CSV export download
    csv_resp = client.get(f"/api/reports/export/csv?dataset_id={sample_dataset}")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers.get("Content-Type", "")

    # JSON export download
    json_resp = client.get(f"/api/reports/export/json?dataset_id={sample_dataset}")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers.get("Content-Type", "")

    # PDF export generation
    pdf_resp = client.post(
        "/api/reports/export/pdf",
        data=json.dumps({"dataset_id": sample_dataset}),
        content_type="application/json"
    )
    assert pdf_resp.status_code == 200
    assert "application/pdf" in pdf_resp.headers.get("Content-Type", "")
