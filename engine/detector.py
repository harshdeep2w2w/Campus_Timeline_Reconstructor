import json
import datetime
from typing import Any, Dict, List, Optional
import dateutil.parser
from database.db import query_db, get_settings
from config import Config


def _parse_epoch(ts: str) -> float:
    """Safely convert timestamp to epoch seconds."""
    try:
        dt = dateutil.parser.parse(ts)
        return dt.timestamp()
    except Exception:
        return 0.0


def get_detection_rules() -> List[Dict[str, Any]]:
    """Return all defined security detection rules with metadata and thresholds."""
    return [
        {
            'name': 'Port Scanning',
            'rule_name': 'Port Scanning',
            'description': 'Detects a single source connecting to multiple distinct destination ports on a single host.',
            'default_threshold': Config.PORT_SCAN_THRESHOLD,
            'severity': 'high'
        },
        {
            'name': 'Repeated Connections',
            'rule_name': 'Repeated Connections',
            'description': 'Detects an unusually high frequency of connections between the same source and destination pair.',
            'default_threshold': Config.REPEATED_CONNECTION_THRESHOLD,
            'severity': 'medium'
        },
        {
            'name': 'Traffic Burst',
            'rule_name': 'Traffic Burst',
            'description': 'Detects rapid bursts of network events originating from a single host within a short time window.',
            'default_threshold': Config.TRAFFIC_BURST_THRESHOLD,
            'severity': 'high'
        },
        {
            'name': 'Suspicious DNS',
            'rule_name': 'Suspicious DNS',
            'description': 'Flags DNS lookups querying known malicious top-level domains (.xyz, .tk, .top, .buzz) or query volume exceeding threshold.',
            'default_threshold': Config.DNS_QUERY_THRESHOLD,
            'severity': 'high'
        },
        {
            'name': 'Unusual Port',
            'rule_name': 'Unusual Port',
            'description': 'Alerts on network activity directed at commonly exploited backdoor, Trojan, or C2 ports.',
            'default_threshold': 'List of known suspicious ports',
            'severity': 'medium'
        },
        {
            'name': 'Network Sweep',
            'rule_name': 'Network Sweep',
            'description': 'Identifies horizontal port scanning or reconnaissance across multiple unique destination hosts.',
            'default_threshold': Config.PORT_SCAN_THRESHOLD,
            'severity': 'high'
        }
    ]


def detect_suspicious_activity(
    dataset_id: Optional[int] = None,
    thresholds: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Analyze events for the specified dataset_id and generate alert records.
    Returns: list of alert dictionaries ready for insertion into the database.
    """
    settings = get_settings()
    thresholds = thresholds or {}

    port_scan_threshold = int(thresholds.get('port_scan_threshold') or settings.get('port_scan_threshold') or Config.PORT_SCAN_THRESHOLD)
    repeated_conn_threshold = int(thresholds.get('repeated_connection_threshold') or settings.get('repeated_connection_threshold') or Config.REPEATED_CONNECTION_THRESHOLD)
    traffic_burst_threshold = int(thresholds.get('traffic_burst_threshold') or settings.get('traffic_burst_threshold') or Config.TRAFFIC_BURST_THRESHOLD)
    dns_query_threshold = int(thresholds.get('dns_query_threshold') or settings.get('dns_query_threshold') or Config.DNS_QUERY_THRESHOLD)
    time_window_sec = int(thresholds.get('time_window_seconds') or settings.get('time_window_seconds') or Config.TIME_WINDOW_SECONDS)

    suspicious_ports_raw = thresholds.get('suspicious_ports') or settings.get('suspicious_ports')
    if suspicious_ports_raw:
        if isinstance(suspicious_ports_raw, str):
            suspicious_ports = [int(p.strip()) for p in suspicious_ports_raw.split(',') if p.strip().isdigit()]
        else:
            suspicious_ports = list(suspicious_ports_raw)
    else:
        suspicious_ports = Config.SUSPICIOUS_PORTS

    where_clause = "WHERE dataset_id = ?" if dataset_id else ""
    params = (dataset_id,) if dataset_id else ()

    events = query_db(
        f"SELECT * FROM events {where_clause} ORDER BY timestamp ASC, id ASC",
        params
    )
    if not events:
        return []

    alerts: List[Dict[str, Any]] = []

    # Attach parsed epochs for time window analysis
    parsed_events = []
    for ev in events:
        c = dict(ev)
        c['_epoch'] = _parse_epoch(ev['timestamp'])
        parsed_events.append(c)

    # -------------------------------------------------------------
    # 1. Unusual Port Detection
    # -------------------------------------------------------------
    for ev in parsed_events:
        dst_p = ev.get('dst_port')
        src_p = ev.get('src_port')
        flagged_port = None
        if dst_p in suspicious_ports:
            flagged_port = dst_p
        elif src_p in suspicious_ports:
            flagged_port = src_p

        if flagged_port is not None:
            sev = 'high' if flagged_port in (4444, 31337, 1337) else 'medium'
            alerts.append({
                'timestamp': ev['timestamp'],
                'alert_type': 'unusual_port',
                'severity': sev,
                'src_ip': ev.get('src_ip'),
                'dst_ip': ev.get('dst_ip'),
                'rule_name': 'Unusual Port',
                'reason': f"Connection involving suspicious/backdoor port {flagged_port} ({ev.get('protocol', 'TCP')})",
                'evidence': json.dumps({
                    'port': flagged_port,
                    'protocol': ev.get('protocol'),
                    'description': ev.get('description')
                }),
                'event_ids': str(ev['id']),
                'dataset_id': ev.get('dataset_id', dataset_id),
                'status': 'open'
            })

    # -------------------------------------------------------------
    # 2. Suspicious DNS Lookups & Query Flooding
    # -------------------------------------------------------------
    suspicious_tlds = ('.xyz', '.tk', '.top', '.buzz', '.bid', '.cc', '.loan')
    dns_by_src: Dict[str, List[Dict[str, Any]]] = {}

    for ev in parsed_events:
        is_dns = ev.get('event_category') == 'DNS' or ev.get('dst_port') == 53 or 'dns' in (ev.get('event_type') or '').lower()
        if not is_dns:
            continue

        src = ev.get('src_ip')
        if src:
            dns_by_src.setdefault(src, []).append(ev)

        # Check hostname / description for suspicious TLDs
        target_name = (ev.get('hostname') or ev.get('description') or '').lower()
        for tld in suspicious_tlds:
            if tld in target_name:
                alerts.append({
                    'timestamp': ev['timestamp'],
                    'alert_type': 'suspicious_dns',
                    'severity': 'high',
                    'src_ip': ev.get('src_ip'),
                    'dst_ip': ev.get('dst_ip'),
                    'rule_name': 'Suspicious DNS',
                    'reason': f"DNS query resolving suspicious top-level domain ({tld}): {target_name}",
                    'evidence': json.dumps({
                        'query': target_name,
                        'tld': tld,
                        'server': ev.get('dst_ip')
                    }),
                    'event_ids': str(ev['id']),
                    'dataset_id': ev.get('dataset_id', dataset_id),
                    'status': 'open'
                })
                break

    # DNS query flood check
    for src, dns_list in dns_by_src.items():
        for i in range(len(dns_list)):
            window = [
                e for e in dns_list[i:]
                if e['_epoch'] - dns_list[i]['_epoch'] <= time_window_sec
            ]
            if len(window) > dns_query_threshold:
                ev_ids = ','.join(str(e['id']) for e in window)
                alerts.append({
                    'timestamp': window[0]['timestamp'],
                    'alert_type': 'suspicious_dns',
                    'severity': 'medium',
                    'src_ip': src,
                    'dst_ip': window[0].get('dst_ip'),
                    'rule_name': 'Suspicious DNS',
                    'reason': f"Excessive DNS query volume from {src} ({len(window)} queries within {time_window_sec}s)",
                    'evidence': json.dumps({
                        'query_count': len(window),
                        'window_seconds': time_window_sec
                    }),
                    'event_ids': ev_ids,
                    'dataset_id': window[0].get('dataset_id', dataset_id),
                    'status': 'open'
                })
                break

    # -------------------------------------------------------------
    # 3. Port Scanning (Vertical)
    # -------------------------------------------------------------
    pair_events: Dict[tuple, List[Dict[str, Any]]] = {}
    for ev in parsed_events:
        src, dst = ev.get('src_ip'), ev.get('dst_ip')
        if src and dst and ev.get('dst_port') is not None:
            pair_events.setdefault((src, dst), []).append(ev)

    for (src, dst), p_events in pair_events.items():
        for i in range(len(p_events)):
            window = [
                e for e in p_events[i:]
                if e['_epoch'] - p_events[i]['_epoch'] <= time_window_sec
            ]
            distinct_ports = {e['dst_port'] for e in window if e.get('dst_port')}
            if len(distinct_ports) >= port_scan_threshold:
                ev_ids = ','.join(str(e['id']) for e in window)
                alerts.append({
                    'timestamp': window[0]['timestamp'],
                    'alert_type': 'port_scan',
                    'severity': 'high',
                    'src_ip': src,
                    'dst_ip': dst,
                    'rule_name': 'Port Scanning',
                    'reason': f"Host {src} connected to {len(distinct_ports)} distinct destination ports on {dst}",
                    'evidence': json.dumps({
                        'scanned_ports': sorted(list(distinct_ports)),
                        'event_count': len(window)
                    }),
                    'event_ids': ev_ids,
                    'dataset_id': window[0].get('dataset_id', dataset_id),
                    'status': 'open'
                })
                break

    # -------------------------------------------------------------
    # 4. Repeated Connections
    # -------------------------------------------------------------
    for (src, dst), p_events in pair_events.items():
        for i in range(len(p_events)):
            window = [
                e for e in p_events[i:]
                if e['_epoch'] - p_events[i]['_epoch'] <= time_window_sec
            ]
            if len(window) >= repeated_conn_threshold:
                ev_ids = ','.join(str(e['id']) for e in window)
                alerts.append({
                    'timestamp': window[0]['timestamp'],
                    'alert_type': 'repeated_connection',
                    'severity': 'medium',
                    'src_ip': src,
                    'dst_ip': dst,
                    'rule_name': 'Repeated Connections',
                    'reason': f"Host {src} initiated {len(window)} repeated connections to {dst} within {time_window_sec}s",
                    'evidence': json.dumps({
                        'connection_count': len(window),
                        'window_seconds': time_window_sec
                    }),
                    'event_ids': ev_ids,
                    'dataset_id': window[0].get('dataset_id', dataset_id),
                    'status': 'open'
                })
                break

    # -------------------------------------------------------------
    # 5. Traffic Burst (High Volume Anomaly)
    # -------------------------------------------------------------
    src_events: Dict[str, List[Dict[str, Any]]] = {}
    for ev in parsed_events:
        src = ev.get('src_ip')
        if src:
            src_events.setdefault(src, []).append(ev)

    for src, s_events in src_events.items():
        for i in range(len(s_events)):
            window = [
                e for e in s_events[i:]
                if e['_epoch'] - s_events[i]['_epoch'] <= time_window_sec
            ]
            if len(window) >= traffic_burst_threshold:
                ev_ids = ','.join(str(e['id']) for e in window[:25])  # Cap ID list string
                alerts.append({
                    'timestamp': window[0]['timestamp'],
                    'alert_type': 'traffic_burst',
                    'severity': 'high',
                    'src_ip': src,
                    'dst_ip': window[0].get('dst_ip'),
                    'rule_name': 'Traffic Burst',
                    'reason': f"Traffic burst of {len(window)} events generated by {src} within {time_window_sec}s",
                    'evidence': json.dumps({
                        'event_count': len(window),
                        'window_seconds': time_window_sec
                    }),
                    'event_ids': ev_ids,
                    'dataset_id': window[0].get('dataset_id', dataset_id),
                    'status': 'open'
                })
                break

    # -------------------------------------------------------------
    # 6. Network Sweep (Horizontal Reconnaissance)
    # -------------------------------------------------------------
    for src, s_events in src_events.items():
        for i in range(len(s_events)):
            window = [
                e for e in s_events[i:]
                if e['_epoch'] - s_events[i]['_epoch'] <= time_window_sec
            ]
            distinct_dsts = {e['dst_ip'] for e in window if e.get('dst_ip')}
            if len(distinct_dsts) >= port_scan_threshold:
                ev_ids = ','.join(str(e['id']) for e in window)
                alerts.append({
                    'timestamp': window[0]['timestamp'],
                    'alert_type': 'network_sweep',
                    'severity': 'high',
                    'src_ip': src,
                    'dst_ip': sorted(list(distinct_dsts))[0],
                    'rule_name': 'Network Sweep',
                    'reason': f"Network sweep detected: {src} contacted {len(distinct_dsts)} distinct destination hosts",
                    'evidence': json.dumps({
                        'contacted_hosts': sorted(list(distinct_dsts)),
                        'event_count': len(window)
                    }),
                    'event_ids': ev_ids,
                    'dataset_id': window[0].get('dataset_id', dataset_id),
                    'status': 'open'
                })
                break

    # Sort alerts chronologically
    alerts.sort(key=lambda a: a['timestamp'])
    return alerts
