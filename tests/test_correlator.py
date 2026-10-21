"""
Tests for engine.correlator module.
Verifies port scan detection, repeated connections, DNS chains, shared hosts,
and finding related events based on temporal and endpoint proximity.
"""
import pytest
from engine.correlator import correlate_events, find_related_events
from database.db import insert_dataset, insert_event


def test_correlate_port_scan(app, sample_dataset):
    """Verify events from one source to many distinct ports on same destination are grouped."""
    with app.app_context():
        # Insert 6 events to different ports within 60 seconds
        ports = [21, 22, 23, 80, 443, 8080]
        for idx, port in enumerate(ports):
            insert_event({
                'dataset_id': sample_dataset,
                'timestamp': f"2024-10-15T09:00:{idx:02d}Z",
                'src_ip': '10.0.1.45',
                'dst_ip': '10.0.2.10',
                'src_port': 50000 + idx,
                'dst_port': port,
                'protocol': 'TCP',
                'event_type': 'scan_probe',
                'description': f"Port probe {port}"
            })

        groups = correlate_events(dataset_id=sample_dataset, time_window=300)
        ps_groups = [g for g in groups if g['correlation_type'] == 'port_scan']
        assert len(ps_groups) >= 1
        assert ps_groups[0]['correlation_type'] == 'port_scan'
        assert '10.0.1.45' in ps_groups[0]['reason']
        assert '10.0.2.10' in ps_groups[0]['reason']


def test_correlate_repeated_connection(app, sample_dataset):
    """Verify repeated connections between same src and dst exceed threshold and group."""
    with app.app_context():
        # Insert 12 connections between same endpoints in 120 seconds
        for i in range(12):
            insert_event({
                'dataset_id': sample_dataset,
                'timestamp': f"2024-10-15T09:10:{i:02d}Z",
                'src_ip': '10.0.1.99',
                'dst_ip': '10.0.2.10',
                'src_port': 40000 + i,
                'dst_port': 22,
                'protocol': 'TCP',
                'event_type': 'ssh_attempt',
                'description': f"SSH connection {i}"
            })

        groups = correlate_events(dataset_id=sample_dataset, time_window=300)
        rc_groups = [g for g in groups if g['correlation_type'] == 'repeated_connection']
        assert len(rc_groups) >= 1
        assert rc_groups[0]['correlation_type'] == 'repeated_connection'
        assert '10.0.1.99' in rc_groups[0]['reason']


def test_correlate_dns_chain(app, sample_dataset):
    """Verify DNS query followed by connection from same client is chained."""
    with app.app_context():
        # DNS lookup
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:20:00Z',
            'src_ip': '10.0.1.33',
            'dst_ip': '10.0.2.1',
            'dst_port': 53,
            'protocol': 'UDP',
            'event_type': 'dns_query',
            'event_category': 'DNS',
            'hostname': 'external-c2.xyz',
            'description': 'DNS Standard Query A external-c2.xyz'
        })
        # Subsequent HTTP connection 15 seconds later
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:20:15Z',
            'src_ip': '10.0.1.33',
            'dst_ip': '203.0.113.50',
            'dst_port': 80,
            'protocol': 'TCP',
            'event_type': 'http_request',
            'event_category': 'HTTP',
            'description': 'HTTP GET /beacon'
        })

        groups = correlate_events(dataset_id=sample_dataset, time_window=300)
        dns_chains = [g for g in groups if g['correlation_type'] == 'dns_connection_chain']
        assert len(dns_chains) >= 1
        assert any('10.0.1.33' in g['reason'] for g in dns_chains)


def test_correlate_shared_host(app):
    """Verify host with multiple interactions across endpoints is grouped."""
    with app.app_context():
        ds_id = insert_dataset({'name': 'Shared Host Set', 'status': 'completed'})
        # Insert 4 events from same src communicating with 2 different destinations
        for i in range(2):
            insert_event({
                'dataset_id': ds_id,
                'timestamp': f"2024-10-15T09:30:0{i}Z",
                'src_ip': '10.0.1.88',
                'dst_ip': '10.0.2.10',
                'dst_port': 80,
                'protocol': 'TCP',
                'description': f"Comm A {i}"
            })
            insert_event({
                'dataset_id': ds_id,
                'timestamp': f"2024-10-15T09:30:1{i}Z",
                'src_ip': '10.0.1.88',
                'dst_ip': '10.0.2.20',
                'dst_port': 25,
                'protocol': 'TCP',
                'description': f"Comm B {i}"
            })

        groups = correlate_events(dataset_id=ds_id, time_window=300)
        sh_groups = [g for g in groups if g['correlation_type'] == 'shared_host']
        assert len(sh_groups) >= 1
        assert '10.0.1.88' in sh_groups[0]['reason']


def test_correlate_no_correlation(app):
    """Verify completely isolated/unrelated events produce no correlation groups."""
    with app.app_context():
        empty_ds = insert_dataset({'name': 'Solitary Set', 'status': 'completed'})
        insert_event({
            'dataset_id': empty_ds,
            'timestamp': '2024-10-15T09:40:00Z',
            'src_ip': '10.0.1.100',
            'dst_ip': '10.0.2.100',
            'dst_port': 80,
            'protocol': 'TCP',
            'description': 'Isolated single ping'
        })

        groups = correlate_events(dataset_id=empty_ds, time_window=300)
        assert len(groups) == 0


def test_find_related_events(app, sample_dataset):
    """Verify find_related_events identifies reverse traffic and shared IP events within window."""
    with app.app_context():
        # Outbound event
        ev1 = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:50:00Z',
            'src_ip': '10.0.1.70',
            'dst_ip': '10.0.2.70',
            'dst_port': 80,
            'protocol': 'TCP',
            'description': 'Outbound client request'
        })
        # Reverse inbound response event 2 seconds later
        ev2 = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:50:02Z',
            'src_ip': '10.0.2.70',
            'dst_ip': '10.0.1.70',
            'src_port': 80,
            'dst_port': 54321,
            'protocol': 'TCP',
            'description': 'Inbound server response'
        })

        related = find_related_events(ev1, time_window=300)
        assert len(related) >= 1
        related_ids = [r['event']['id'] for r in related]
        assert ev2 in related_ids


def test_find_related_events_no_matches(app, sample_dataset):
    """Verify isolated event with unique endpoints returns no related events."""
    with app.app_context():
        isolated_id = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T07:00:00Z',
            'src_ip': '172.16.0.99',
            'dst_ip': '172.16.0.100',
            'protocol': 'ICMP',
            'description': 'Isolated ICMP echo'
        })

        related = find_related_events(isolated_id, time_window=300)
        assert len(related) == 0


def test_time_window_respected(app, sample_dataset):
    """Verify events outside the specified time window are not correlated or related."""
    with app.app_context():
        ev_base = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T08:00:00Z',
            'src_ip': '10.0.1.66',
            'dst_ip': '10.0.2.66',
            'protocol': 'TCP',
            'description': 'Early session'
        })
        # Event 1 hour later
        ev_late = insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T09:00:00Z',
            'src_ip': '10.0.1.66',
            'dst_ip': '10.0.2.66',
            'protocol': 'TCP',
            'description': 'Late session'
        })

        # With 300 second (5 min) time window, ev_late is not related to ev_base
        related = find_related_events(ev_base, time_window=300)
        related_ids = [r['event']['id'] for r in related]
        assert ev_late not in related_ids
