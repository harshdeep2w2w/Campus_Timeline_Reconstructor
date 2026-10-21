"""
Tests for engine.detector module.
Verifies detection of port scanning, repeated connections, traffic bursts,
suspicious DNS queries, unusual ports, network sweeps, and custom thresholds.
"""
import pytest
from engine.detector import detect_suspicious_activity, get_detection_rules
from database.db import insert_dataset, insert_event


def test_detect_port_scanning(app, sample_dataset):
    """Verify port scan generates high-severity alert with rule_name 'Port Scanning'."""
    with app.app_context():
        # Connect to 6 distinct ports on same target
        ports = [21, 22, 25, 80, 443, 8080]
        for idx, port in enumerate(ports):
            insert_event({
                'dataset_id': sample_dataset,
                'timestamp': f"2024-10-15T08:00:{idx:02d}Z",
                'src_ip': '10.0.1.45',
                'dst_ip': '10.0.2.10',
                'dst_port': port,
                'protocol': 'TCP',
                'description': f"Scan port {port}"
            })

        alerts = detect_suspicious_activity(dataset_id=sample_dataset)
        scan_alerts = [a for a in alerts if a['rule_name'] == 'Port Scanning']
        assert len(scan_alerts) >= 1
        alert = scan_alerts[0]
        assert alert['alert_type'] == 'port_scan'
        assert alert['severity'] == 'high'
        assert alert['src_ip'] == '10.0.1.45'
        assert alert['dst_ip'] == '10.0.2.10'
        assert 'distinct destination ports' in alert['reason']


def test_detect_repeated_connections(app, sample_dataset):
    """Verify repeated connections pattern generates alert."""
    with app.app_context():
        # 12 repeated connections between same pair
        for i in range(12):
            insert_event({
                'dataset_id': sample_dataset,
                'timestamp': f"2024-10-15T08:05:{i:02d}Z",
                'src_ip': '10.0.1.99',
                'dst_ip': '10.0.2.15',
                'dst_port': 80,
                'protocol': 'TCP',
                'description': f"Repeated connection {i}"
            })

        alerts = detect_suspicious_activity(dataset_id=sample_dataset)
        rc_alerts = [a for a in alerts if a['rule_name'] == 'Repeated Connections']
        assert len(rc_alerts) >= 1
        alert = rc_alerts[0]
        assert alert['alert_type'] == 'repeated_connection'
        assert alert['severity'] == 'medium'
        assert alert['src_ip'] == '10.0.1.99'
        assert alert['dst_ip'] == '10.0.2.15'


def test_detect_traffic_burst(app):
    """Verify rapid burst of traffic from one source triggers alert."""
    with app.app_context():
        ds_id = insert_dataset({'name': 'Burst Set', 'status': 'completed'})
        # Use custom threshold of 10 events within window
        for i in range(15):
            insert_event({
                'dataset_id': ds_id,
                'timestamp': f"2024-10-15T08:10:{i:02d}Z",
                'src_ip': '10.0.1.50',
                'dst_ip': '10.0.2.10',
                'dst_port': 80,
                'protocol': 'TCP',
                'description': f"Burst hit {i}"
            })

        alerts = detect_suspicious_activity(dataset_id=ds_id, thresholds={'traffic_burst_threshold': 10})
        burst_alerts = [a for a in alerts if a['rule_name'] == 'Traffic Burst']
        assert len(burst_alerts) >= 1
        assert burst_alerts[0]['severity'] == 'high'
        assert burst_alerts[0]['src_ip'] == '10.0.1.50'


def test_detect_suspicious_dns(app, sample_dataset):
    """Verify DNS queries to suspicious TLDs (.xyz, .tk, .top) generate alerts."""
    with app.app_context():
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T08:15:00Z',
            'src_ip': '10.0.1.45',
            'dst_ip': '10.0.2.1',
            'dst_port': 53,
            'protocol': 'UDP',
            'event_type': 'dns_query',
            'event_category': 'DNS',
            'hostname': 'malware-c2.xyz',
            'description': 'DNS Standard Query A malware-c2.xyz'
        })

        alerts = detect_suspicious_activity(dataset_id=sample_dataset)
        dns_alerts = [a for a in alerts if a['rule_name'] == 'Suspicious DNS']
        assert len(dns_alerts) >= 1
        alert = dns_alerts[0]
        assert alert['severity'] == 'high'
        assert alert['src_ip'] == '10.0.1.45'
        assert '.xyz' in alert['reason']


def test_detect_unusual_port(app, sample_dataset):
    """Verify connection to unusual port 4444 generates high severity alert."""
    with app.app_context():
        insert_event({
            'dataset_id': sample_dataset,
            'timestamp': '2024-10-15T08:20:00Z',
            'src_ip': '10.0.1.45',
            'dst_ip': '203.0.113.50',
            'src_port': 54321,
            'dst_port': 4444,
            'protocol': 'TCP',
            'description': 'Backdoor reverse shell communication'
        })

        alerts = detect_suspicious_activity(dataset_id=sample_dataset)
        port_alerts = [a for a in alerts if a['rule_name'] == 'Unusual Port']
        assert len(port_alerts) >= 1
        alert = port_alerts[0]
        assert alert['severity'] == 'high'
        assert alert['src_ip'] == '10.0.1.45'
        assert alert['dst_ip'] == '203.0.113.50'
        assert '4444' in alert['reason']


def test_detect_network_sweep(app):
    """Verify horizontal scanning (one IP connecting to many different destination IPs)."""
    with app.app_context():
        ds_id = insert_dataset({'name': 'Sweep Set', 'status': 'completed'})
        # 10.0.1.78 connects to 6 different target IPs on port 445
        for i in range(1, 7):
            insert_event({
                'dataset_id': ds_id,
                'timestamp': f"2024-10-15T08:25:{i:02d}Z",
                'src_ip': '10.0.1.78',
                'dst_ip': f"10.0.3.{i}",
                'dst_port': 445,
                'protocol': 'TCP',
                'description': f"SMB probe to 10.0.3.{i}"
            })

        alerts = detect_suspicious_activity(dataset_id=ds_id)
        sweep_alerts = [a for a in alerts if a['rule_name'] == 'Network Sweep']
        assert len(sweep_alerts) >= 1
        alert = sweep_alerts[0]
        assert alert['severity'] == 'high'
        assert alert['src_ip'] == '10.0.1.78'
        assert 'distinct destination hosts' in alert['reason']


def test_detect_no_suspicious(app):
    """Verify normal traffic generates no security alerts."""
    with app.app_context():
        ds_id = insert_dataset({'name': 'Clean Set', 'status': 'completed'})
        # Insert completely normal traffic to benign destinations
        insert_event({
            'dataset_id': ds_id,
            'timestamp': '2024-10-15T08:30:00Z',
            'src_ip': '10.0.1.15',
            'dst_ip': '10.0.2.1',
            'dst_port': 53,
            'protocol': 'UDP',
            'hostname': 'portal.campus.edu',
            'description': 'DNS Query portal.campus.edu'
        })
        insert_event({
            'dataset_id': ds_id,
            'timestamp': '2024-10-15T08:30:10Z',
            'src_ip': '10.0.1.15',
            'dst_ip': '10.0.2.10',
            'dst_port': 80,
            'protocol': 'TCP',
            'description': 'HTTP GET /login'
        })

        alerts = detect_suspicious_activity(dataset_id=ds_id)
        assert len(alerts) == 0


def test_custom_thresholds(app):
    """Verify overriding detection thresholds modifies alert trigger sensitivity."""
    with app.app_context():
        ds_id = insert_dataset({'name': 'Thresholds Set', 'status': 'completed'})
        # Connect to 2 distinct ports (normally below default threshold of 5)
        insert_event({
            'dataset_id': ds_id,
            'timestamp': '2024-10-15T08:35:00Z',
            'src_ip': '10.0.1.90',
            'dst_ip': '10.0.2.10',
            'dst_port': 80,
            'protocol': 'TCP'
        })
        insert_event({
            'dataset_id': ds_id,
            'timestamp': '2024-10-15T08:35:01Z',
            'src_ip': '10.0.1.90',
            'dst_ip': '10.0.2.10',
            'dst_port': 443,
            'protocol': 'TCP'
        })

        # Default threshold (5) -> no port scan alert
        alerts_default = detect_suspicious_activity(dataset_id=ds_id)
        assert len([a for a in alerts_default if a['rule_name'] == 'Port Scanning']) == 0

        # Custom threshold (2) -> port scan alert triggered
        alerts_custom = detect_suspicious_activity(dataset_id=ds_id, thresholds={'port_scan_threshold': 2})
        scan_alerts = [a for a in alerts_custom if a['rule_name'] == 'Port Scanning']
        assert len(scan_alerts) == 1
        assert scan_alerts[0]['src_ip'] == '10.0.1.90'


def test_get_detection_rules():
    """Verify get_detection_rules returns a list of rule definitions with required attributes."""
    rules = get_detection_rules()
    assert isinstance(rules, list)
    assert len(rules) >= 6

    rule_names = [r['name'] for r in rules]
    assert 'Port Scanning' in rule_names
    assert 'Repeated Connections' in rule_names
    assert 'Traffic Burst' in rule_names
    assert 'Suspicious DNS' in rule_names
    assert 'Unusual Port' in rule_names
    assert 'Network Sweep' in rule_names

    for rule in rules:
        assert 'description' in rule
        assert 'default_threshold' in rule
        assert 'severity' in rule
