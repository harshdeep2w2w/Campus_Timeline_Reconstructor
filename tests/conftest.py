"""
Pytest configuration and fixtures for Campus Network Attack - Timeline Reconstructor.
"""
import os
import tempfile
import shutil
import pytest

from app import create_app
from database.db import (
    get_db,
    init_db,
    insert_dataset,
    insert_event,
    update_hosts
)


@pytest.fixture(scope="session")
def test_temp_dir():
    """Create a temporary root directory for the test session."""
    temp_dir = tempfile.mkdtemp(prefix="timeline_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def app(test_temp_dir):
    """
    Create Flask app configured with temporary SQLite database and upload folder.
    Yields app and cleans up database file afterwards.
    """
    db_fd, db_path = tempfile.mkstemp(prefix="test_db_", suffix=".db", dir=test_temp_dir)
    os.close(db_fd)

    upload_folder = tempfile.mkdtemp(prefix="test_uploads_", dir=test_temp_dir)

    test_config = {
        'TESTING': True,
        'DATABASE': db_path,
        'UPLOAD_FOLDER': upload_folder,
        'SECRET_KEY': 'test-secret-key-12345',
        'WTF_CSRF_ENABLED': False,
    }

    application = create_app(test_config=test_config)

    with application.app_context():
        init_db()

    yield application

    # Teardown
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass
    shutil.rmtree(upload_folder, ignore_errors=True)


@pytest.fixture
def client(app):
    """Flask test client fixture."""
    return app.test_client()


@pytest.fixture
def db(app):
    """Database connection fixture within application context."""
    with app.app_context():
        yield get_db()


@pytest.fixture
def sample_dataset(app):
    """Insert a test dataset record and return its id."""
    with app.app_context():
        dataset_id = insert_dataset({
            'name': 'Test Dataset Alpha',
            'filename': 'test_alpha.csv',
            'file_type': 'csv',
            'status': 'completed',
            'record_count': 5,
            'description': 'Integration testing dataset'
        })
        return dataset_id


@pytest.fixture
def sample_events(app, sample_dataset):
    """Insert standard test events into sample_dataset and return list of event ids."""
    with app.app_context():
        event_ids = []
        events_data = [
            {
                'dataset_id': sample_dataset,
                'timestamp': '2024-10-15T08:00:00Z',
                'src_ip': '10.0.1.15',
                'dst_ip': '10.0.2.1',
                'src_port': 51234,
                'dst_port': 53,
                'protocol': 'UDP',
                'event_type': 'dns_query',
                'event_category': 'DNS',
                'hostname': 'portal.campus.edu',
                'log_source': 'zeek_dns',
                'description': 'DNS Query portal.campus.edu',
                'severity': 'informational',
                'raw_data': '{"query": "portal.campus.edu"}'
            },
            {
                'dataset_id': sample_dataset,
                'timestamp': '2024-10-15T08:01:00Z',
                'src_ip': '10.0.1.15',
                'dst_ip': '10.0.2.10',
                'src_port': 51235,
                'dst_port': 80,
                'protocol': 'TCP',
                'event_type': 'http_request',
                'event_category': 'HTTP',
                'hostname': 'portal.campus.edu',
                'log_source': 'zeek_http',
                'description': 'HTTP GET /login',
                'severity': 'informational',
                'raw_data': '{"uri": "/login"}'
            },
            {
                'dataset_id': sample_dataset,
                'timestamp': '2024-10-15T08:02:00Z',
                'src_ip': '10.0.1.45',
                'dst_ip': '10.0.2.10',
                'src_port': 52001,
                'dst_port': 22,
                'protocol': 'TCP',
                'event_type': 'ssh_connection',
                'event_category': 'SSH',
                'hostname': 'core-server',
                'log_source': 'zeek_conn',
                'description': 'SSH connection attempt',
                'severity': 'medium',
                'raw_data': '{"service": "ssh"}'
            },
            {
                'dataset_id': sample_dataset,
                'timestamp': '2024-10-15T08:03:00Z',
                'src_ip': '10.0.1.45',
                'dst_ip': '203.0.113.50',
                'src_port': 52002,
                'dst_port': 4444,
                'protocol': 'TCP',
                'event_type': 'connection',
                'event_category': 'General Connection',
                'hostname': 'external-c2',
                'log_source': 'zeek_conn',
                'description': 'TCP connection to port 4444',
                'severity': 'high',
                'raw_data': '{"note": "c2 beacon"}'
            },
            {
                'dataset_id': sample_dataset,
                'timestamp': '2024-10-15T08:04:00Z',
                'src_ip': '10.0.1.78',
                'dst_ip': '10.0.3.1',
                'src_port': 53001,
                'dst_port': 445,
                'protocol': 'TCP',
                'event_type': 'smb_connection',
                'event_category': 'SMB',
                'hostname': 'admin-dc',
                'log_source': 'zeek_conn',
                'description': 'SMB probe connection',
                'severity': 'low',
                'raw_data': '{"service": "smb"}'
            }
        ]

        for ev in events_data:
            ev_id = insert_event(ev)
            event_ids.append(ev_id)

        update_hosts(sample_dataset)
        return event_ids


@pytest.fixture
def sample_csv_file(test_temp_dir):
    """Create a temporary CSV file with test event data and return its path."""
    csv_path = os.path.join(test_temp_dir, "test_events.csv")
    content = (
        "timestamp,source_ip,dest_ip,source_port,dest_port,protocol,event_type,severity,description\n"
        "2024-10-15T08:10:00Z,10.0.1.20,10.0.2.10,55123,80,TCP,http,informational,Web access to intranet\n"
        "2024-10-15T08:11:00Z,10.0.1.20,10.0.2.1,55124,53,UDP,dns,informational,DNS resolve campus.edu\n"
        "2024-10-15T08:12:00Z,10.0.1.45,10.0.2.10,55125,4444,TCP,backdoor,high,Suspicious payload transfer\n"
    )
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write(content)

    yield csv_path

    if os.path.exists(csv_path):
        try:
            os.remove(csv_path)
        except OSError:
            pass


@pytest.fixture
def sample_json_file(test_temp_dir):
    """Create a temporary JSON file with test event data and return its path."""
    json_path = os.path.join(test_temp_dir, "test_events.json")
    content = """[
  {
    "timestamp": "2024-10-15T08:20:00Z",
    "src_ip": "10.0.1.30",
    "dst_ip": "10.0.2.20",
    "src_port": 56000,
    "dst_port": 25,
    "protocol": "TCP",
    "event_type": "smtp_transfer",
    "severity": "informational",
    "description": "Outbound email dispatch"
  },
  {
    "timestamp": "2024-10-15T08:21:00Z",
    "src_ip": "10.0.1.45",
    "dst_ip": "10.0.2.10",
    "src_port": 56001,
    "dst_port": 3389,
    "protocol": "TCP",
    "event_type": "rdp_attempt",
    "severity": "medium",
    "description": "RDP connection to server"
  }
]"""
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(content)

    yield json_path

    if os.path.exists(json_path):
        try:
            os.remove(json_path)
        except OSError:
            pass
