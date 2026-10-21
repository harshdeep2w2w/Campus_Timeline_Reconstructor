import os
import tempfile
import datetime
from typing import Any, Dict, List, Optional
from flask import Blueprint, request, jsonify, current_app, send_file
from werkzeug.utils import secure_filename

from database.db import (
    query_db,
    execute_db,
    insert_dataset,
    update_dataset,
    get_dataset,
    get_all_datasets,
    delete_dataset,
    insert_event,
    insert_events_batch,
    get_events,
    get_event,
    get_hosts,
    get_host_detail,
    update_hosts,
    insert_alert,
    get_alerts,
    get_alert,
    update_alert_status,
    delete_alerts_by_dataset,
    get_investigations,
    get_investigation,
    create_investigation,
    update_investigation,
    delete_investigation,
    add_events_to_investigation,
    add_hosts_to_investigation,
    remove_event_from_investigation,
    get_dashboard_stats,
    get_activity_over_time,
    get_top_hosts,
    get_protocol_distribution,
    get_settings,
    update_settings,
)
from parsers.csv_parser import parse_csv
from parsers.json_parser import parse_json
from parsers.zeek_parser import parse_zeek_log
from engine.timeline import reconstruct_timeline, get_event_detail
from engine.correlator import correlate_events, find_related_events
from engine.detector import detect_suspicious_activity, get_detection_rules
from synthetic.generator import load_sample_data
from reports.generator import export_events_csv, export_events_json, generate_pdf_report

api_bp = Blueprint('api', __name__)


# ---------------------------------------------------------------------------
# Dashboard Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/dashboard/stats', methods=['GET'])
def api_dashboard_stats():
    """Retrieve aggregate telemetry and alert stats."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        stats = get_dashboard_stats(dataset_id)
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/dashboard/activity-over-time', methods=['GET'])
def api_dashboard_activity_over_time():
    """Retrieve hourly event volume distribution."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        activity = get_activity_over_time(dataset_id)
        return jsonify(activity), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/dashboard/top-hosts', methods=['GET'])
def api_dashboard_top_hosts():
    """Retrieve most active source and destination endpoints."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        limit = request.args.get('limit', default=10, type=int)
        top_hosts = get_top_hosts(dataset_id, limit)
        return jsonify(top_hosts), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/dashboard/protocol-distribution', methods=['GET'])
def api_dashboard_protocol_distribution():
    """Retrieve distribution of network protocols."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        distribution = get_protocol_distribution(dataset_id)
        return jsonify(distribution), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/dashboard/recent-alerts', methods=['GET'])
def api_dashboard_recent_alerts():
    """Retrieve most recent threat detection alerts."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        limit = request.args.get('limit', default=10, type=int)

        where_clause = "WHERE dataset_id = ?" if dataset_id else ""
        params = [dataset_id, limit] if dataset_id else [limit]

        query = f"""
            SELECT id, timestamp, severity, rule_name, reason, src_ip, dst_ip
            FROM alerts
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        recent = query_db(query, params)
        return jsonify(recent), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Ingestion / Upload Endpoint
# ---------------------------------------------------------------------------

@api_bp.route('/upload', methods=['POST'])
def api_upload_file():
    """
    Ingest and process uploaded log file (CSV, JSON, Zeek TSV).
    Auto-detects format, normalizes records, detects threats, and generates preview.
    """
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file part in request'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No selected file'}), 400

        dataset_name = request.form.get('dataset_name', '').strip()
        if not dataset_name:
            dataset_name = file.filename

        filename = secure_filename(file.filename)
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        save_path = os.path.join(upload_folder, f"{int(datetime.datetime.now().timestamp())}_{filename}")
        file.save(save_path)

        # Detect parser format
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        file_type = ext

        records: List[Dict[str, Any]] = []
        errors: List[str] = []

        if ext in ('csv', 'tsv'):
            records, errors = parse_csv(save_path)
            file_type = 'csv'
        elif ext == 'json':
            records, errors = parse_json(save_path)
            file_type = 'json'
        else:
            # Check file header for Zeek or JSON markers
            with open(save_path, 'r', encoding='utf-8', errors='replace') as peek_f:
                header_content = peek_f.read(1024).strip()

            if header_content.startswith('#separator') or header_content.startswith('#fields'):
                records, errors = parse_zeek_log(save_path)
                file_type = 'zeek'
            elif header_content.startswith('{') or header_content.startswith('['):
                records, errors = parse_json(save_path)
                file_type = 'json'
            else:
                # Default to CSV parser
                records, errors = parse_csv(save_path)
                file_type = 'csv'

        # Record dataset
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        dataset_id = insert_dataset({
            'name': dataset_name,
            'filename': filename,
            'file_type': file_type,
            'upload_time': now_iso,
            'record_count': len(records),
            'status': 'ready' if records else 'error',
            'errors': '; '.join(errors[:5]) if errors else None,
            'description': f"Ingested from {filename} with {len(records)} events."
        })

        if records:
            for r in records:
                r['dataset_id'] = dataset_id

            # Batch insert
            insert_events_batch(records)

            # Threat detection
            alerts = detect_suspicious_activity(dataset_id=dataset_id)
            for a in alerts:
                insert_alert(a)

            # Update hosts
            update_hosts(dataset_id=dataset_id)

        preview = records[:5] if records else []
        return jsonify({
            'success': True,
            'dataset_id': dataset_id,
            'record_count': len(records),
            'errors': errors[:10],
            'preview': preview
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Timeline Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/timeline/events', methods=['GET'])
def api_timeline_events():
    """Retrieve chronological event records with pagination and criteria filtering."""
    try:
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=50, type=int)

        filters = {
            'dataset_id': request.args.get('dataset_id', type=int),
            'time_start': request.args.get('time_start'),
            'time_end': request.args.get('time_end'),
            'src_ip': request.args.get('src_ip'),
            'dst_ip': request.args.get('dst_ip'),
            'protocol': request.args.get('protocol'),
            'severity': request.args.get('severity'),
            'category': request.args.get('category'),
            'search': request.args.get('search')
        }
        res = get_events(filters=filters, page=page, per_page=per_page)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/timeline/event/<int:id>', methods=['GET'])
def api_timeline_event_detail(id: int):
    """Retrieve single event detail including temporally and logically correlated events."""
    try:
        detail = get_event_detail(id)
        if not detail:
            return jsonify({'error': 'Event not found'}), 404
        return jsonify(detail), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Correlation Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/correlation/related/<int:event_id>', methods=['GET'])
def api_correlation_related(event_id: int):
    """Find all related network events linked to a focal event."""
    try:
        event = get_event(event_id)
        if not event:
            return jsonify({'error': 'Event not found'}), 404

        time_window = request.args.get('time_window', default=300, type=int)
        related = find_related_events(event_id, time_window=time_window)
        return jsonify({
            'event': event,
            'related_events': related
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/correlation/groups', methods=['GET'])
def api_correlation_groups():
    """Retrieve correlated incident groups across a dataset."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        time_window = request.args.get('time_window', default=300, type=int)
        groups = correlate_events(dataset_id=dataset_id, time_window=time_window)
        return jsonify(groups), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Network Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/network/graph', methods=['GET'])
def api_network_graph():
    """
    Generate graph topology (nodes and edges) for interactive network visualization.
    Nodes represent hosts, edges represent communications with event counts and protocols.
    """
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        time_start = request.args.get('time_start')
        time_end = request.args.get('time_end')
        category = request.args.get('category')

        conditions = ["src_ip IS NOT NULL", "dst_ip IS NOT NULL", "src_ip != ''", "dst_ip != ''"]
        params = []

        if dataset_id:
            conditions.append("dataset_id = ?")
            params.append(dataset_id)
        if time_start:
            conditions.append("timestamp >= ?")
            params.append(time_start)
        if time_end:
            conditions.append("timestamp <= ?")
            params.append(time_end)
        if category:
            conditions.append("LOWER(event_category) = LOWER(?)")
            params.append(category)

        where_clause = "WHERE " + " AND ".join(conditions)

        # Query communication edges
        edge_query = f"""
            SELECT 
                src_ip as source,
                dst_ip as target,
                COUNT(*) as count,
                GROUP_CONCAT(DISTINCT protocol) as protocols
            FROM events
            {where_clause}
            GROUP BY src_ip, dst_ip
            ORDER BY count DESC
            LIMIT 500
        """
        raw_edges = query_db(edge_query, params)

        edges = []
        node_ip_set = set()
        for e in raw_edges:
            edges.append({
                'source': e['source'],
                'target': e['target'],
                'count': e['count'],
                'protocols': [p.strip() for p in (e['protocols'] or '').split(',') if p.strip()]
            })
            node_ip_set.add(e['source'])
            node_ip_set.add(e['target'])

        if not node_ip_set:
            return jsonify({'nodes': [], 'edges': []}), 200

        # Query node metadata (hostname, event count, suspicious status)
        suspicious_hosts = set()
        susp_query = "SELECT DISTINCT src_ip FROM alerts WHERE src_ip IS NOT NULL"
        if dataset_id:
            susp_query += " AND dataset_id = ?"
            al_rows = query_db(susp_query, (dataset_id,))
        else:
            al_rows = query_db(susp_query)
        for r in al_rows:
            suspicious_hosts.add(r['src_ip'])

        # Fetch host details
        placeholders = ','.join(['?'] * len(node_ip_set))
        host_query = f"""
            SELECT ip_address, hostname, event_count 
            FROM hosts 
            WHERE ip_address IN ({placeholders})
        """
        host_rows = query_db(host_query, list(node_ip_set))
        host_map = {h['ip_address']: h for h in host_rows}

        nodes = []
        for ip in sorted(list(node_ip_set)):
            meta = host_map.get(ip, {})
            is_susp = ip in suspicious_hosts
            nodes.append({
                'id': ip,
                'label': meta.get('hostname') or ip,
                'hostname': meta.get('hostname'),
                'event_count': meta.get('event_count', 1),
                'is_suspicious': is_susp
            })

        return jsonify({'nodes': nodes, 'edges': edges}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/network/host/<ip>', methods=['GET'])
def api_network_host_detail(ip: str):
    """Retrieve complete dossier on a network host by IP."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        detail = get_host_detail(ip, dataset_id)
        return jsonify(detail), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Alerts Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/alerts', methods=['GET'])
def api_alerts_list():
    """List threat alerts with pagination and filtering."""
    try:
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=50, type=int)
        filters = {
            'dataset_id': request.args.get('dataset_id', type=int),
            'severity': request.args.get('severity'),
            'status': request.args.get('status')
        }
        res = get_alerts(filters=filters, page=page, per_page=per_page)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/alerts/<int:id>', methods=['GET'])
def api_alert_detail(id: int):
    """Retrieve single alert with its associated telemetry events."""
    try:
        alert = get_alert(id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404

        associated_events = []
        if alert.get('event_ids'):
            id_strs = [i.strip() for i in str(alert['event_ids']).split(',') if i.strip().isdigit()]
            if id_strs:
                placeholders = ','.join(['?'] * len(id_strs))
                ev_query = f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY timestamp ASC"
                associated_events = query_db(ev_query, [int(i) for i in id_strs])

        result = dict(alert)
        result['associated_events'] = associated_events
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/alerts/<int:id>', methods=['PATCH'])
def api_alert_update_status(id: int):
    """Update status of alert (open, acknowledged, resolved, false_positive)."""
    try:
        data = request.get_json() or {}
        new_status = data.get('status')
        if not new_status:
            return jsonify({'success': False, 'error': 'Missing status'}), 400

        update_alert_status(id, new_status)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Investigations Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/investigations', methods=['GET'])
def api_investigations_list():
    """List all incident investigations."""
    try:
        investigations = get_investigations()
        return jsonify(investigations), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/investigations', methods=['POST'])
def api_investigations_create():
    """Create a new investigation case."""
    try:
        data = request.get_json() or {}
        if not data.get('title'):
            return jsonify({'success': False, 'error': 'Title is required'}), 400

        inv_id = create_investigation(data)
        return jsonify({'success': True, 'id': inv_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/investigations/<int:id>', methods=['GET'])
def api_investigation_detail(id: int):
    """Retrieve investigation case details with pinned events, hosts, and stats."""
    try:
        inv = get_investigation(id)
        if not inv:
            return jsonify({'error': 'Investigation not found'}), 404
        return jsonify(inv), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/investigations/<int:id>', methods=['PUT'])
def api_investigation_update(id: int):
    """Update investigation metadata, status, or analyst notes."""
    try:
        data = request.get_json() or {}
        update_investigation(id, data)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/investigations/<int:id>', methods=['DELETE'])
def api_investigation_delete(id: int):
    """Delete an investigation case."""
    try:
        delete_investigation(id)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/investigations/<int:id>/events', methods=['POST'])
def api_investigation_add_events(id: int):
    """Pin multiple events to an investigation."""
    try:
        data = request.get_json() or {}
        event_ids = data.get('event_ids', [])
        added = add_events_to_investigation(id, event_ids)
        return jsonify({'success': True, 'added': added}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/investigations/<int:id>/hosts', methods=['POST'])
def api_investigation_add_hosts(id: int):
    """Pin host IPs to an investigation."""
    try:
        data = request.get_json() or {}
        host_ips = data.get('host_ips', [])
        add_hosts_to_investigation(id, host_ips)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/investigations/<int:id>/events/<int:event_id>', methods=['DELETE'])
def api_investigation_remove_event(id: int, event_id: int):
    """Unpin an event from an investigation."""
    try:
        remove_event_from_investigation(id, event_id)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Datasets Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/datasets', methods=['GET'])
def api_datasets_list():
    """List all uploaded datasets."""
    try:
        datasets = get_all_datasets()
        return jsonify(datasets), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/datasets/<int:id>', methods=['DELETE'])
def api_datasets_delete(id: int):
    """Delete dataset and all cascaded telemetry."""
    try:
        delete_dataset(id)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/datasets/load-sample', methods=['POST'])
def api_datasets_load_sample():
    """Generate and load rich synthetic campus network attack telemetry."""
    try:
        dataset_id = load_sample_data()
        return jsonify({
            'success': True,
            'dataset_id': dataset_id,
            'message': 'Sample dataset loaded and analyzed successfully'
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_bp.route('/datasets/<int:id>/preview', methods=['GET'])
def api_datasets_preview(id: int):
    """Retrieve dataset details and first N events."""
    try:
        limit = request.args.get('limit', default=20, type=int)
        ds = get_dataset(id)
        if not ds:
            return jsonify({'error': 'Dataset not found'}), 404

        records = query_db(
            "SELECT * FROM events WHERE dataset_id = ? ORDER BY timestamp ASC, id ASC LIMIT ?",
            (id, limit)
        )
        return jsonify({
            'dataset': ds,
            'records': records
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Reports & Forensic Export Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/reports/export/csv', methods=['GET'])
def api_reports_export_csv():
    """Export dataset or investigation events to a CSV file download."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        inv_id = request.args.get('investigation_id', type=int)

        events: List[Dict[str, Any]] = []
        filename = f"events_export_{int(datetime.datetime.now().timestamp())}.csv"

        if inv_id:
            inv = get_investigation(inv_id)
            if inv:
                events = inv.get('events', [])
                filename = f"investigation_{inv_id}_events.csv"
        elif dataset_id:
            events = reconstruct_timeline(dataset_id=dataset_id)
            filename = f"dataset_{dataset_id}_events.csv"
        else:
            events = query_db("SELECT * FROM events ORDER BY timestamp ASC LIMIT 5000")

        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)
        export_events_csv(events, filepath)

        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/reports/export/json', methods=['GET'])
def api_reports_export_json():
    """Export dataset or investigation events to a JSON file download."""
    try:
        dataset_id = request.args.get('dataset_id', type=int)
        inv_id = request.args.get('investigation_id', type=int)

        events: List[Dict[str, Any]] = []
        filename = f"events_export_{int(datetime.datetime.now().timestamp())}.json"

        if inv_id:
            inv = get_investigation(inv_id)
            if inv:
                events = inv.get('events', [])
                filename = f"investigation_{inv_id}_events.json"
        elif dataset_id:
            events = reconstruct_timeline(dataset_id=dataset_id)
            filename = f"dataset_{dataset_id}_events.json"
        else:
            events = query_db("SELECT * FROM events ORDER BY timestamp ASC LIMIT 5000")

        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)
        export_events_json(events, filepath)

        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/reports/export/pdf', methods=['POST'])
def api_reports_export_pdf():
    """Compile and generate executive PDF incident report."""
    try:
        data = request.get_json() or {}
        inv_id = data.get('investigation_id')
        dataset_id = data.get('dataset_id')

        report_data = {
            'investigation': None,
            'dataset': None,
            'stats': {},
            'alerts': [],
            'events': [],
            'hosts': []
        }

        filename = f"investigation_report_{int(datetime.datetime.now().timestamp())}.pdf"

        if inv_id:
            inv = get_investigation(int(inv_id))
            if inv:
                report_data['investigation'] = inv
                report_data['events'] = inv.get('events', [])
                # Hosts
                if inv.get('hosts'):
                    placeholders = ','.join(['?'] * len(inv['hosts']))
                    report_data['hosts'] = query_db(
                        f"SELECT * FROM hosts WHERE ip_address IN ({placeholders})",
                        inv['hosts']
                    )
                # Alerts
                if inv.get('dataset_id'):
                    report_data['alerts'] = query_db(
                        "SELECT * FROM alerts WHERE dataset_id = ? ORDER BY timestamp DESC",
                        (inv['dataset_id'],)
                    )
                report_data['stats'] = {
                    'total_events': len(report_data['events']),
                    'unique_hosts': len(report_data['hosts']),
                    'alerts_count': len(report_data['alerts'])
                }
                filename = f"investigation_{inv_id}_report.pdf"

        elif dataset_id:
            ds = get_dataset(int(dataset_id))
            report_data['dataset'] = ds
            report_data['events'] = reconstruct_timeline(dataset_id=int(dataset_id))[:100]
            report_data['alerts'] = query_db(
                "SELECT * FROM alerts WHERE dataset_id = ? ORDER BY timestamp DESC",
                (int(dataset_id),)
            )
            report_data['hosts'] = get_hosts(dataset_id=int(dataset_id))
            report_data['stats'] = get_dashboard_stats(dataset_id=int(dataset_id))
            filename = f"dataset_{dataset_id}_report.pdf"

        else:
            report_data['events'] = query_db("SELECT * FROM events ORDER BY timestamp ASC LIMIT 100")
            report_data['alerts'] = query_db("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20")
            report_data['hosts'] = get_hosts()[:15]
            report_data['stats'] = get_dashboard_stats()

        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)
        generate_pdf_report(report_data, filepath)

        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Settings Endpoints
# ---------------------------------------------------------------------------

@api_bp.route('/settings', methods=['GET'])
def api_settings_get():
    """Retrieve security rules and system settings."""
    try:
        settings = get_settings()
        rules = get_detection_rules()
        return jsonify({
            'settings': settings,
            'rules': rules
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/settings', methods=['PUT'])
def api_settings_update():
    """Update system detection threshold settings."""
    try:
        data = request.get_json() or {}
        update_settings(data)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
