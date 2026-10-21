import os
import sqlite3
import datetime
import math
from typing import Any, Dict, List, Optional, Tuple, Union
from flask import current_app, g, has_app_context
from config import Config

# Exact SQL schema specification
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    filename TEXT,
    file_type TEXT,
    upload_time TEXT NOT NULL,
    record_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'processing',
    errors TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    event_type TEXT,
    event_category TEXT,
    hostname TEXT,
    log_source TEXT,
    description TEXT,
    severity TEXT DEFAULT 'informational',
    raw_data TEXT,
    normalized INTEGER DEFAULT 0,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    first_seen TEXT,
    last_seen TEXT,
    event_count INTEGER DEFAULT 0,
    dataset_id INTEGER,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    rule_name TEXT NOT NULL,
    reason TEXT,
    evidence TEXT,
    event_ids TEXT,
    dataset_id INTEGER,
    status TEXT DEFAULT 'open',
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT,
    time_range_start TEXT,
    time_range_end TEXT,
    analyst_notes TEXT,
    findings TEXT,
    dataset_id INTEGER,
    FOREIGN KEY (dataset_id) REFERENCES datasets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS investigation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    UNIQUE(investigation_id, event_id)
);

CREATE TABLE IF NOT EXISTS investigation_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER NOT NULL,
    host_ip TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
    UNIQUE(investigation_id, host_ip)
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT
);
"""


import shutil

def ensure_database_file(db_path: str) -> None:
    """Ensure database directory exists and copy seed database if missing on Vercel."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    if not os.path.exists(db_path):
        seed_path = os.path.join(Config.BASE_DIR, 'database', 'seed_campus_timeline.db')
        if os.path.exists(seed_path):
            try:
                shutil.copyfile(seed_path, db_path)
            except Exception:
                pass


def get_db() -> sqlite3.Connection:
    """
    Get SQLite database connection for the current Flask context or create a standalone one.
    Configured with sqlite3.Row row_factory and foreign keys enabled.
    """
    if has_app_context():
        if '_database' not in g:
            db_path = current_app.config.get('DATABASE', Config.DATABASE)
            ensure_database_file(db_path)
            conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            g._database = conn
        return g._database
    else:
        db_path = Config.DATABASE
        ensure_database_file(db_path)
        conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn


def close_db(e: Optional[BaseException] = None) -> None:
    """Close the database connection at the end of the Flask application context."""
    if has_app_context():
        db = g.pop('_database', None)
        if db is not None:
            db.close()


def init_db() -> None:
    """Initialize database schema and populate default application settings."""
    db = get_db()
    db.executescript(SCHEMA_SQL)

    # Insert default settings if not existing
    default_settings = [
        ('repeated_connection_threshold', str(Config.REPEATED_CONNECTION_THRESHOLD)),
        ('port_scan_threshold', str(Config.PORT_SCAN_THRESHOLD)),
        ('traffic_burst_threshold', str(Config.TRAFFIC_BURST_THRESHOLD)),
        ('time_window_seconds', str(Config.TIME_WINDOW_SECONDS)),
        ('dns_query_threshold', str(Config.DNS_QUERY_THRESHOLD)),
        ('suspicious_ports', ','.join(map(str, Config.SUSPICIOUS_PORTS)))
    ]

    for key, value in default_settings:
        db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value)
        )
    db.commit()

    # Ensure default dataset exists so timeline and alerts never render empty on cold start
    try:
        cur = db.execute("SELECT COUNT(*) as cnt FROM datasets")
        row = cur.fetchone()
        if not row or row['cnt'] == 0:
            from synthetic.generator import load_sample_data
            load_sample_data()
    except Exception:
        pass


def init_app(app) -> None:
    """Register database teardown callback and initialize schema within app context."""
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()


def query_db(query: str, args: Union[Tuple, List] = (), one: bool = False) -> Any:
    """Execute a SELECT query and return list of dicts or a single dict."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    if one:
        return dict(rv[0]) if rv else None
    return [dict(row) for row in rv]


def execute_db(query: str, args: Union[Tuple, List] = (), commit: bool = True) -> int:
    """Execute an INSERT, UPDATE, or DELETE query and return cursor.lastrowid."""
    db = get_db()
    cur = db.execute(query, args)
    if commit:
        db.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id


# ---------------------------------------------------------------------------
# Datasets CRUD
# ---------------------------------------------------------------------------

def insert_dataset(data: Dict[str, Any]) -> int:
    """Insert a new dataset record."""
    upload_time = data.get('upload_time') or datetime.datetime.now(datetime.timezone.utc).isoformat()
    return execute_db(
        """
        INSERT INTO datasets (name, filename, file_type, upload_time, record_count, status, errors, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get('name', 'Untitled Dataset'),
            data.get('filename'),
            data.get('file_type'),
            upload_time,
            data.get('record_count', 0),
            data.get('status', 'processing'),
            data.get('errors'),
            data.get('description')
        )
    )


def update_dataset(dataset_id: int, data: Dict[str, Any]) -> None:
    """Update existing dataset record fields."""
    allowed_fields = ['name', 'filename', 'file_type', 'record_count', 'status', 'errors', 'description']
    set_clauses = []
    values = []
    for field in allowed_fields:
        if field in data:
            set_clauses.append(f"{field} = ?")
            values.append(data[field])

    if set_clauses:
        values.append(dataset_id)
        execute_db(
            f"UPDATE datasets SET {', '.join(set_clauses)} WHERE id = ?",
            values
        )


def get_dataset(dataset_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve single dataset by id."""
    return query_db("SELECT * FROM datasets WHERE id = ?", (dataset_id,), one=True)


def get_all_datasets() -> List[Dict[str, Any]]:
    """Retrieve all datasets ordered by upload_time descending."""
    return query_db("SELECT * FROM datasets ORDER BY id DESC")


def delete_dataset(dataset_id: int) -> bool:
    """Delete dataset by id (cascades to events, alerts, hosts, investigations)."""
    execute_db("DELETE FROM datasets WHERE id = ?", (dataset_id,))
    return True


# ---------------------------------------------------------------------------
# Events CRUD
# ---------------------------------------------------------------------------

def insert_event(data: Dict[str, Any]) -> int:
    """Insert a single event record."""
    return execute_db(
        """
        INSERT INTO events (
            dataset_id, timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, event_type, event_category, hostname, log_source,
            description, severity, raw_data, normalized
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data['dataset_id'],
            data['timestamp'],
            data.get('src_ip'),
            data.get('dst_ip'),
            data.get('src_port'),
            data.get('dst_port'),
            data.get('protocol'),
            data.get('event_type'),
            data.get('event_category'),
            data.get('hostname'),
            data.get('log_source'),
            data.get('description'),
            data.get('severity', 'informational'),
            data.get('raw_data'),
            data.get('normalized', 1)
        )
    )


def insert_events_batch(events_list: List[Dict[str, Any]]) -> int:
    """Batch insert multiple events in a single transaction."""
    if not events_list:
        return 0

    db = get_db()
    sql = """
        INSERT INTO events (
            dataset_id, timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, event_type, event_category, hostname, log_source,
            description, severity, raw_data, normalized
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = [
        (
            e['dataset_id'],
            e['timestamp'],
            e.get('src_ip'),
            e.get('dst_ip'),
            e.get('src_port'),
            e.get('dst_port'),
            e.get('protocol'),
            e.get('event_type'),
            e.get('event_category'),
            e.get('hostname'),
            e.get('log_source'),
            e.get('description'),
            e.get('severity', 'informational'),
            e.get('raw_data'),
            e.get('normalized', 1)
        )
        for e in events_list
    ]
    cur = db.executemany(sql, params)
    db.commit()
    count = cur.rowcount
    cur.close()
    return count


def get_events(
    filters: Optional[Dict[str, Any]] = None,
    page: int = 1,
    per_page: int = 50
) -> Dict[str, Any]:
    """
    Retrieve paginated events with optional filtering.
    Returns: {events, total, page, pages, per_page}
    """
    filters = filters or {}
    conditions = []
    params = []

    if filters.get('dataset_id') is not None and str(filters['dataset_id']).strip() != '':
        conditions.append("dataset_id = ?")
        params.append(int(filters['dataset_id']))

    if filters.get('src_ip'):
        conditions.append("src_ip = ?")
        params.append(filters['src_ip'])

    if filters.get('dst_ip'):
        conditions.append("dst_ip = ?")
        params.append(filters['dst_ip'])

    if filters.get('protocol'):
        conditions.append("UPPER(protocol) = UPPER(?)")
        params.append(filters['protocol'])

    if filters.get('severity'):
        conditions.append("LOWER(severity) = LOWER(?)")
        params.append(filters['severity'])

    category = filters.get('event_category') or filters.get('category')
    if category:
        conditions.append("LOWER(event_category) = LOWER(?)")
        params.append(category)

    if filters.get('time_start'):
        conditions.append("timestamp >= ?")
        params.append(filters['time_start'])

    if filters.get('time_end'):
        conditions.append("timestamp <= ?")
        params.append(filters['time_end'])

    if filters.get('search'):
        search_pattern = f"%{filters['search']}%"
        conditions.append("(description LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR hostname LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    count_query = f"SELECT COUNT(*) as total FROM events {where_clause}"
    count_res = query_db(count_query, params, one=True)
    total = count_res['total'] if count_res else 0

    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 1000))
    pages = max(1, math.ceil(total / per_page)) if total > 0 else 1
    offset = (page - 1) * per_page

    data_query = f"""
        SELECT * FROM events {where_clause}
        ORDER BY timestamp ASC, id ASC
        LIMIT ? OFFSET ?
    """
    events = query_db(data_query, params + [per_page, offset])

    return {
        'events': events,
        'total': total,
        'page': page,
        'pages': pages,
        'per_page': per_page
    }


def get_event(event_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single event by id."""
    return query_db("SELECT * FROM events WHERE id = ?", (event_id,), one=True)


# ---------------------------------------------------------------------------
# Hosts CRUD & Host Detail
# ---------------------------------------------------------------------------

def get_hosts(dataset_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieve host records optionally filtered by dataset_id."""
    if dataset_id:
        return query_db(
            "SELECT * FROM hosts WHERE dataset_id = ? ORDER BY event_count DESC",
            (dataset_id,)
        )
    return query_db("SELECT * FROM hosts ORDER BY event_count DESC")


def get_host_detail(ip: str, dataset_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Retrieve comprehensive details for a host by IP address.
    Calculates connections, communication partners, first/last seen, and recent events.
    """
    base_filter = "WHERE (src_ip = ? OR dst_ip = ?)"
    params = [ip, ip]
    if dataset_id:
        base_filter += " AND dataset_id = ?"
        params.append(dataset_id)

    # General host summary
    host_summary = query_db(
        f"""
        SELECT 
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen,
            COUNT(*) as total_events
        FROM events {base_filter}
        """,
        params,
        one=True
    )

    # Hostname resolution if recorded
    host_row = query_db(
        "SELECT hostname FROM hosts WHERE ip_address = ? AND (? IS NULL OR dataset_id = ?) LIMIT 1",
        (ip, dataset_id, dataset_id),
        one=True
    )
    hostname = host_row['hostname'] if host_row and host_row['hostname'] else None

    # Connections breakdown (peer IPs, direction, counts)
    connections_query = f"""
        SELECT 
            CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END as remote_ip,
            CASE WHEN src_ip = ? THEN 'outbound' ELSE 'inbound' END as direction,
            COUNT(*) as count
        FROM events {base_filter}
        GROUP BY remote_ip, direction
        ORDER BY count DESC
        LIMIT 25
    """
    conn_params = [ip, ip] + params
    connections = query_db(connections_query, conn_params)

    # Recent events involving host
    recent_events_query = f"""
        SELECT * FROM events {base_filter}
        ORDER BY timestamp DESC
        LIMIT 20
    """
    recent_events = query_db(recent_events_query, params)

    return {
        'ip': ip,
        'hostname': hostname,
        'first_seen': host_summary['first_seen'] if host_summary else None,
        'last_seen': host_summary['last_seen'] if host_summary else None,
        'event_count': host_summary['total_events'] if host_summary else 0,
        'connections': connections,
        'recent_events': recent_events
    }


def update_hosts(dataset_id: Optional[int] = None) -> None:
    """
    Aggregate events to refresh or populate the hosts table.
    Collects first_seen, last_seen, event_count, and hostname for each unique IP.
    """
    db = get_db()
    if dataset_id:
        db.execute("DELETE FROM hosts WHERE dataset_id = ?", (dataset_id,))
    else:
        db.execute("DELETE FROM hosts")
    db.commit()

    where_clause = "WHERE dataset_id = ?" if dataset_id else ""
    args = (dataset_id,) if dataset_id else ()

    # Group all distinct IPs involved in traffic
    query = f"""
        WITH ip_activity AS (
            SELECT dataset_id, src_ip AS ip_address, hostname, timestamp FROM events {where_clause}
            UNION ALL
            SELECT dataset_id, dst_ip AS ip_address, NULL as hostname, timestamp FROM events {where_clause}
        )
        SELECT 
            ip_address,
            MAX(hostname) as hostname,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen,
            COUNT(*) as event_count,
            dataset_id
        FROM ip_activity
        WHERE ip_address IS NOT NULL AND TRIM(ip_address) != ''
        GROUP BY dataset_id, ip_address
    """
    records = query_db(query, args + args if dataset_id else ())

    for r in records:
        execute_db(
            """
            INSERT INTO hosts (ip_address, hostname, first_seen, last_seen, event_count, dataset_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (r['ip_address'], r['hostname'], r['first_seen'], r['last_seen'], r['event_count'], r['dataset_id']),
            commit=False
        )
    db.commit()


# ---------------------------------------------------------------------------
# Alerts CRUD
# ---------------------------------------------------------------------------

def insert_alert(data: Dict[str, Any]) -> int:
    """Insert a new alert record."""
    return execute_db(
        """
        INSERT INTO alerts (
            timestamp, alert_type, severity, src_ip, dst_ip,
            rule_name, reason, evidence, event_ids, dataset_id, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data['timestamp'],
            data['alert_type'],
            data['severity'],
            data.get('src_ip'),
            data.get('dst_ip'),
            data['rule_name'],
            data.get('reason'),
            data.get('evidence'),
            data.get('event_ids'),
            data.get('dataset_id'),
            data.get('status', 'open')
        )
    )


def get_alerts(
    filters: Optional[Dict[str, Any]] = None,
    page: int = 1,
    per_page: int = 50
) -> Dict[str, Any]:
    """Retrieve paginated alerts with filtering."""
    filters = filters or {}
    conditions = []
    params = []

    if filters.get('dataset_id') is not None and str(filters['dataset_id']).strip() != '':
        conditions.append("dataset_id = ?")
        params.append(int(filters['dataset_id']))

    if filters.get('severity'):
        conditions.append("LOWER(severity) = LOWER(?)")
        params.append(filters['severity'])

    if filters.get('status'):
        conditions.append("LOWER(status) = LOWER(?)")
        params.append(filters['status'])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    count_res = query_db(f"SELECT COUNT(*) as total FROM alerts {where_clause}", params, one=True)
    total = count_res['total'] if count_res else 0

    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 1000))
    pages = max(1, math.ceil(total / per_page)) if total > 0 else 1
    offset = (page - 1) * per_page

    data_query = f"""
        SELECT * FROM alerts {where_clause}
        ORDER BY timestamp DESC, id DESC
        LIMIT ? OFFSET ?
    """
    alerts = query_db(data_query, params + [per_page, offset])

    return {
        'alerts': alerts,
        'total': total,
        'page': page,
        'pages': pages
    }


def get_alert(alert_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve single alert by id."""
    return query_db("SELECT * FROM alerts WHERE id = ?", (alert_id,), one=True)


def update_alert_status(alert_id: int, status: str) -> None:
    """Update status of alert (open, acknowledged, resolved, false_positive)."""
    execute_db("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))


def delete_alerts_by_dataset(dataset_id: int) -> None:
    """Delete all alerts for a given dataset."""
    execute_db("DELETE FROM alerts WHERE dataset_id = ?", (dataset_id,))


# ---------------------------------------------------------------------------
# Investigations CRUD
# ---------------------------------------------------------------------------

def get_investigations() -> List[Dict[str, Any]]:
    """Retrieve all investigations with counted associated events."""
    query = """
        SELECT 
            i.*,
            COUNT(DISTINCT ie.event_id) as event_count
        FROM investigations i
        LEFT JOIN investigation_events ie ON i.id = ie.investigation_id
        GROUP BY i.id
        ORDER BY i.created_at DESC
    """
    return query_db(query)


def get_investigation(investigation_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve single investigation with attached events, hosts, and alert count.
    """
    inv = query_db("SELECT * FROM investigations WHERE id = ?", (investigation_id,), one=True)
    if not inv:
        return None

    # Associated events
    events = query_db(
        """
        SELECT e.* FROM events e
        JOIN investigation_events ie ON e.id = ie.event_id
        WHERE ie.investigation_id = ?
        ORDER BY e.timestamp ASC
        """,
        (investigation_id,)
    )

    # Associated hosts
    hosts = query_db(
        "SELECT host_ip FROM investigation_hosts WHERE investigation_id = ?",
        (investigation_id,)
    )
    host_list = [h['host_ip'] for h in hosts]

    # Count alerts related to the investigation's dataset or events
    alert_count = 0
    if inv.get('dataset_id'):
        al_res = query_db(
            "SELECT COUNT(*) as cnt FROM alerts WHERE dataset_id = ?",
            (inv['dataset_id'],),
            one=True
        )
        alert_count = al_res['cnt'] if al_res else 0

    inv['events'] = events
    inv['hosts'] = host_list
    inv['alert_count'] = alert_count
    return inv


def create_investigation(data: Dict[str, Any]) -> int:
    """Create a new investigation."""
    created_at = data.get('created_at') or datetime.datetime.now(datetime.timezone.utc).isoformat()
    return execute_db(
        """
        INSERT INTO investigations (
            title, description, status, created_at, updated_at,
            time_range_start, time_range_end, analyst_notes, findings, dataset_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data['title'],
            data.get('description'),
            data.get('status', 'open'),
            created_at,
            created_at,
            data.get('time_range_start'),
            data.get('time_range_end'),
            data.get('analyst_notes'),
            data.get('findings'),
            data.get('dataset_id')
        )
    )


def update_investigation(investigation_id: int, data: Dict[str, Any]) -> None:
    """Update investigation details and update timestamp."""
    allowed_fields = [
        'title', 'description', 'status', 'time_range_start',
        'time_range_end', 'analyst_notes', 'findings', 'dataset_id'
    ]
    set_clauses = ["updated_at = ?"]
    values = [datetime.datetime.now(datetime.timezone.utc).isoformat()]

    for field in allowed_fields:
        if field in data:
            set_clauses.append(f"{field} = ?")
            values.append(data[field])

    values.append(investigation_id)
    execute_db(
        f"UPDATE investigations SET {', '.join(set_clauses)} WHERE id = ?",
        values
    )


def delete_investigation(investigation_id: int) -> bool:
    """Delete investigation by id."""
    execute_db("DELETE FROM investigations WHERE id = ?", (investigation_id,))
    return True


def add_events_to_investigation(investigation_id: int, event_ids: List[int]) -> int:
    """Link multiple events to an investigation."""
    if not event_ids:
        return 0
    db = get_db()
    added = 0
    for eid in event_ids:
        try:
            db.execute(
                "INSERT OR IGNORE INTO investigation_events (investigation_id, event_id) VALUES (?, ?)",
                (investigation_id, int(eid))
            )
            added += 1
        except Exception:
            continue
    db.commit()
    return added


def add_hosts_to_investigation(investigation_id: int, host_ips: List[str]) -> int:
    """Link multiple host IPs to an investigation."""
    if not host_ips:
        return 0
    db = get_db()
    added = 0
    for ip in host_ips:
        if not ip:
            continue
        try:
            db.execute(
                "INSERT OR IGNORE INTO investigation_hosts (investigation_id, host_ip) VALUES (?, ?)",
                (investigation_id, str(ip).strip())
            )
            added += 1
        except Exception:
            continue
    db.commit()
    return added


def remove_event_from_investigation(investigation_id: int, event_id: int) -> bool:
    """Remove a linked event from an investigation."""
    execute_db(
        "DELETE FROM investigation_events WHERE investigation_id = ? AND event_id = ?",
        (investigation_id, event_id)
    )
    return True


# ---------------------------------------------------------------------------
# Dashboard Analytics
# ---------------------------------------------------------------------------

def get_dashboard_stats(dataset_id: Optional[int] = None) -> Dict[str, Any]:
    """Retrieve high-level dashboard metrics and alert distribution."""
    event_cond = "WHERE dataset_id = ?" if dataset_id else ""
    event_params = (dataset_id,) if dataset_id else ()

    # Total events
    ev_res = query_db(f"SELECT COUNT(*) as cnt FROM events {event_cond}", event_params, one=True)
    total_events = ev_res['cnt'] if ev_res else 0

    # Unique hosts
    if dataset_id:
        uh_res = query_db(
            """
            SELECT COUNT(DISTINCT ip) as cnt FROM (
                SELECT src_ip as ip FROM events WHERE dataset_id = ? AND src_ip IS NOT NULL AND src_ip != ''
                UNION
                SELECT dst_ip as ip FROM events WHERE dataset_id = ? AND dst_ip IS NOT NULL AND dst_ip != ''
            )
            """,
            (dataset_id, dataset_id),
            one=True
        )
    else:
        uh_res = query_db(
            """
            SELECT COUNT(DISTINCT ip) as cnt FROM (
                SELECT src_ip as ip FROM events WHERE src_ip IS NOT NULL AND src_ip != ''
                UNION
                SELECT dst_ip as ip FROM events WHERE dst_ip IS NOT NULL AND dst_ip != ''
            )
            """,
            one=True
        )
    unique_hosts = uh_res['cnt'] if uh_res else 0

    # Suspicious events (high or critical severity)
    susp_cond = f"WHERE severity IN ('high', 'critical')"
    if dataset_id:
        susp_cond += " AND dataset_id = ?"
    susp_res = query_db(f"SELECT COUNT(*) as cnt FROM events {susp_cond}", (dataset_id,) if dataset_id else (), one=True)
    suspicious_events = susp_res['cnt'] if susp_res else 0

    # Active investigations
    inv_cond = "WHERE status != 'closed'"
    if dataset_id:
        inv_cond += " AND dataset_id = ?"
    inv_res = query_db(f"SELECT COUNT(*) as cnt FROM investigations {inv_cond}", (dataset_id,) if dataset_id else (), one=True)
    active_investigations = inv_res['cnt'] if inv_res else 0

    # Alerts by severity breakdown
    al_cond = "WHERE dataset_id = ?" if dataset_id else ""
    al_rows = query_db(
        f"SELECT LOWER(severity) as severity, COUNT(*) as cnt FROM alerts {al_cond} GROUP BY LOWER(severity)",
        (dataset_id,) if dataset_id else ()
    )
    alerts_by_sev = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'informational': 0
    }
    for row in al_rows:
        sev = row['severity']
        if sev in alerts_by_sev:
            alerts_by_sev[sev] = row['cnt']

    return {
        'total_events': total_events,
        'unique_hosts': unique_hosts,
        'suspicious_events': suspicious_events,
        'active_investigations': active_investigations,
        'alerts_by_severity': alerts_by_sev
    }


def get_activity_over_time(dataset_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Group events into hourly buckets for timeline trend chart."""
    where_clause = "WHERE dataset_id = ?" if dataset_id else ""
    params = (dataset_id,) if dataset_id else ()

    query = f"""
        SELECT 
            substr(timestamp, 1, 13) || ':00' as time_bucket,
            COUNT(*) as count
        FROM events
        {where_clause}
        WHERE timestamp IS NOT NULL AND timestamp != ''
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
    """
    # Adjust for SQLite where clause combination
    if where_clause:
        query = f"""
            SELECT 
                substr(timestamp, 1, 13) || ':00' as time_bucket,
                COUNT(*) as count
            FROM events
            WHERE dataset_id = ? AND timestamp IS NOT NULL AND timestamp != ''
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
        """
    return query_db(query, params)


def get_top_hosts(dataset_id: Optional[int] = None, limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    """Retrieve top source and destination IPs by event frequency."""
    limit = max(1, min(int(limit), 100))
    where_clause = "WHERE dataset_id = ? AND " if dataset_id else "WHERE "
    params = [dataset_id] if dataset_id else []

    top_src_query = f"""
        SELECT src_ip as ip, COUNT(*) as count
        FROM events
        {where_clause} src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT ?
    """
    top_sources = query_db(top_src_query, params + [limit])

    top_dst_query = f"""
        SELECT dst_ip as ip, COUNT(*) as count
        FROM events
        {where_clause} dst_ip IS NOT NULL AND dst_ip != ''
        GROUP BY dst_ip
        ORDER BY count DESC
        LIMIT ?
    """
    top_destinations = query_db(top_dst_query, params + [limit])

    return {
        'top_sources': top_sources,
        'top_destinations': top_destinations
    }


def get_protocol_distribution(dataset_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieve breakdown of event counts by network protocol."""
    where_clause = "WHERE dataset_id = ? AND " if dataset_id else "WHERE "
    params = [dataset_id] if dataset_id else []

    query = f"""
        SELECT UPPER(protocol) as protocol, COUNT(*) as count
        FROM events
        {where_clause} protocol IS NOT NULL AND protocol != ''
        GROUP BY UPPER(protocol)
        ORDER BY count DESC
    """
    return query_db(query, params)


# ---------------------------------------------------------------------------
# Settings CRUD
# ---------------------------------------------------------------------------

def get_settings() -> Dict[str, str]:
    """Retrieve all application configuration settings as a key-value dictionary."""
    rows = query_db("SELECT key, value FROM settings")
    return {row['key']: row['value'] for row in rows}


def update_settings(data: Dict[str, Any]) -> None:
    """Update or insert application settings."""
    db = get_db()
    for key, value in data.items():
        db.execute(
            """
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (str(key), str(value))
        )
    db.commit()
