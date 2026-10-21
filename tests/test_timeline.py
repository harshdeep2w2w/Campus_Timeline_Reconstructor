"""
Tests for engine.timeline module.
Verifies timeline reconstruction, sorting, filtering, and event detail with correlation.
"""
import pytest
from engine.timeline import reconstruct_timeline, get_event_detail
from database.db import insert_dataset, insert_event


def test_reconstruct_timeline_chronological(app, sample_dataset):
    """Verify events are returned in strict chronological order (ascending timestamp)."""
    with app.app_context():
        # Insert events in non-chronological order
        t3 = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:30:00Z',
            'src_ip': '10.0.1.10',
            'dst_ip': '10.0.2.10',
            'protocol': 'TCP',
            'event_type': 'test3',
            'severity': 'low'
        })
        t1 = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T08:15:00Z',
            'src_ip': '10.0.1.10',
            'dst_ip': '10.0.2.10',
            'protocol': 'TCP',
            'event_type': 'test1',
            'severity': 'informational'
        })
        t2 = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:00:00Z',
            'src_ip': '10.0.1.10',
            'dst_ip': '10.0.2.10',
            'protocol': 'TCP',
            'event_type': 'test2',
            'severity': 'medium'
        })

        timeline = reconstruct_timeline(dataset_id=sample_dataset)
        assert len(timeline) >= 3

        # Verify timestamps are strictly increasing
        timestamps = [e['timestamp'] for e in timeline]
        assert timestamps == sorted(timestamps)


def test_reconstruct_timeline_with_filters(app, sample_dataset):
    """Verify filtering by src_ip, protocol, and severity."""
    with app.app_context():
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T10:00:00Z',
            'src_ip': '10.0.1.99',
            'dst_ip': '10.0.2.10',
            'protocol': 'UDP',
            'severity': 'critical',
            'description': 'Unique UDP flood'
        })
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T10:01:00Z',
            'src_ip': '10.0.1.99',
            'dst_ip': '10.0.2.10',
            'protocol': 'TCP',
            'severity': 'high',
            'description': 'TCP probe'
        })

        # Filter by src_ip
        res_ip = reconstruct_timeline(dataset_id=sample_dataset, filters={'src_ip': '10.0.1.99'})
        assert all(e['src_ip'] == '10.0.1.99' for e in res_ip)
        assert len(res_ip) == 2

        # Filter by protocol
        res_proto = reconstruct_timeline(dataset_id=sample_dataset, filters={'src_ip': '10.0.1.99', 'protocol': 'UDP'})
        assert len(res_proto) == 1
        assert res_proto[0]['protocol'] == 'UDP'

        # Filter by severity
        res_sev = reconstruct_timeline(dataset_id=sample_dataset, filters={'severity': 'critical'})
        assert len(res_sev) >= 1
        assert all(e['severity'] == 'critical' for e in res_sev)


def test_reconstruct_timeline_empty_dataset(app):
    """Verify reconstruct_timeline returns an empty list for a dataset with no events."""
    with app.app_context():
        empty_ds_id = insert_dataset({
            'name': 'Empty Set',
            'status': 'completed'
        })
        timeline = reconstruct_timeline(dataset_id=empty_ds_id)
        assert timeline == []


def test_get_event_detail(app, sample_dataset):
    """Verify get_event_detail returns complete event fields."""
    with app.app_context():
        ev_id = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T11:00:00Z',
            'src_ip': '10.0.1.25',
            'dst_ip': '10.0.2.10',
            'src_port': 40000,
            'dst_port': 443,
            'protocol': 'TCP',
            'event_type': 'https_conn',
            'event_category': 'TLS/HTTPS',
            'hostname': 'secure.campus.edu',
            'log_source': 'zeek_ssl',
            'description': 'TLS Handshake',
            'severity': 'informational'
        })

        detail = get_event_detail(ev_id)
        assert detail is not None
        assert detail['id'] == ev_id
        assert detail['src_ip'] == '10.0.1.25'
        assert detail['dst_ip'] == '10.0.2.10'
        assert detail['dst_port'] == 443
        assert detail['event_category'] == 'TLS/HTTPS'
        assert 'related_events' in detail


def test_get_event_detail_with_related(app, sample_dataset):
    """Verify related events within 5-minute window sharing IP are included."""
    with app.app_context():
        # Target event
        target_id = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T12:00:00Z',
            'src_ip': '10.0.1.55',
            'dst_ip': '10.0.2.50',
            'protocol': 'TCP',
            'description': 'Primary connection'
        })

        # Related event within 2 minutes with same src_ip
        related_id = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T12:02:00Z',
            'src_ip': '10.0.1.55',
            'dst_ip': '10.0.2.99',
            'protocol': 'TCP',
            'description': 'Related subsequent connection'
        })

        # Distant event > 10 minutes away
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T12:20:00Z',
            'src_ip': '10.0.1.55',
            'dst_ip': '10.0.2.50',
            'protocol': 'TCP',
            'description': 'Far future connection'
        })

        detail = get_event_detail(target_id)
        assert detail is not None
        related_ids = [e['id'] for e in detail['related_events']]
        assert related_id in related_ids
        assert target_id not in related_ids


def test_get_event_detail_nonexistent(app):
    """Verify get_event_detail returns None for an invalid event ID."""
    with app.app_context():
        res = get_event_detail(999999)
        assert res is None
