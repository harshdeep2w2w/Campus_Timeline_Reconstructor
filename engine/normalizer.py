import re
import json
import datetime
from typing import Any, Dict, Optional, Union
import dateutil.parser


def normalize_timestamp(ts: Any) -> str:
    """
    Normalize various timestamp formats into a standard ISO 8601 string.
    Handles Unix timestamps (seconds, milliseconds, float/int strings),
    ISO 8601, and arbitrary date string formats.
    """
    if ts is None:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    if isinstance(ts, (int, float)):
        # Check if timestamp is in milliseconds (> year 2286 in seconds)
        if ts > 1e11:
            ts = ts / 1000.0
        try:
            dt = datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc)
            return dt.isoformat()
        except (ValueError, OverflowError, OSError):
            return datetime.datetime.now(datetime.timezone.utc).isoformat()

    ts_str = str(ts).strip()
    if not ts_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Try numeric string (e.g. Zeek unix timestamps '1729000000.123')
    try:
        val = float(ts_str)
        if val > 1e11:
            val = val / 1000.0
        dt = datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc)
        return dt.isoformat()
    except (ValueError, OverflowError, OSError):
        pass

    # Try dateutil parser
    try:
        dt = dateutil.parser.parse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


def normalize_ip(ip: Any) -> Optional[str]:
    """Normalize and clean IP address string."""
    if ip is None:
        return None
    ip_str = str(ip).strip().strip("[]'\"")
    if not ip_str or ip_str in ('-', 'null', 'None', 'NaN'):
        return None
    return ip_str


def normalize_port(port: Any) -> Optional[int]:
    """Normalize port number to an integer between 0 and 65535."""
    if port is None:
        return None
    port_str = str(port).strip()
    if not port_str or port_str in ('-', 'null', 'None', 'NaN'):
        return None
    try:
        port_num = int(float(port_str))
        if 0 <= port_num <= 65535:
            return port_num
        return None
    except (ValueError, TypeError):
        return None


def normalize_protocol(proto: Any) -> str:
    """Normalize protocol names (e.g. TCP, UDP, ICMP)."""
    if proto is None:
        return 'TCP'
    p = str(proto).strip().upper()
    if not p or p in ('-', 'NULL', 'NONE'):
        return 'TCP'
    # Handle protocol numbers
    proto_map = {
        '6': 'TCP',
        '17': 'UDP',
        '1': 'ICMP',
        '2': 'IGMP',
        '47': 'GRE',
        '50': 'ESP'
    }
    return proto_map.get(p, p)


def normalize_severity(sev: Any) -> str:
    """
    Normalize severity levels into standard categories:
    critical, high, medium, low, informational.
    """
    if sev is None:
        return 'informational'
    s = str(sev).strip().lower()
    mapping = {
        'crit': 'critical',
        'critical': 'critical',
        'fatal': 'critical',
        'severe': 'critical',
        'high': 'high',
        'err': 'high',
        'error': 'high',
        'med': 'medium',
        'medium': 'medium',
        'warn': 'medium',
        'warning': 'medium',
        'low': 'low',
        'notice': 'low',
        'info': 'informational',
        'informational': 'informational',
        'debug': 'informational'
    }
    return mapping.get(s, 'informational')


def categorize_event(event_dict: Dict[str, Any]) -> str:
    """
    Determine the event_category based on event_type, port numbers,
    protocol, and description.
    """
    existing_cat = event_dict.get('event_category') or event_dict.get('category')
    if existing_cat and str(existing_cat).strip() and str(existing_cat).strip().lower() != 'none':
        return str(existing_cat).strip()

    dst_port = normalize_port(event_dict.get('dst_port'))
    src_port = normalize_port(event_dict.get('src_port'))
    event_type = str(event_dict.get('event_type') or '').lower()
    description = str(event_dict.get('description') or '').lower()

    # Port-based matching
    ports = {dst_port, src_port}
    if 53 in ports or 'dns' in event_type or 'dns' in description:
        return 'DNS'
    if 67 in ports or 68 in ports or 'dhcp' in event_type or 'dhcp' in description:
        return 'DHCP'
    if 443 in ports or 8443 in ports or 'tls' in event_type or 'ssl' in event_type or 'https' in description:
        return 'TLS/HTTPS'
    if 80 in ports or 8080 in ports or 8000 in ports or 'http' in event_type:
        return 'HTTP'
    if 22 in ports or 'ssh' in event_type or 'ssh' in description:
        return 'SSH'
    if 25 in ports or 465 in ports or 587 in ports or 'smtp' in event_type or 'mail' in description:
        return 'SMTP'
    if 20 in ports or 21 in ports or 'ftp' in event_type:
        return 'FTP'
    if 445 in ports or 139 in ports or 'smb' in event_type:
        return 'SMB'
    if 3389 in ports or 'rdp' in event_type:
        return 'RDP'
    if any(p in ports for p in (3306, 5432, 1433, 1521, 27017)):
        return 'Database'
    if 'scan' in event_type or 'scan' in description or 'sweep' in description:
        return 'Reconnaissance'
    if 'burst' in description or 'burst' in event_type:
        return 'Traffic Burst'

    return 'General Connection'


def normalize_event(event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standardize a raw event dictionary into the full application schema.
    """
    raw_copy = dict(event_dict)
    raw_data_str = raw_copy.get('raw_data')
    if raw_data_str is None:
        try:
            raw_data_str = json.dumps(raw_copy, default=str)
        except Exception:
            raw_data_str = str(raw_copy)

    norm_timestamp = normalize_timestamp(event_dict.get('timestamp') or event_dict.get('time') or event_dict.get('ts'))
    norm_src_ip = normalize_ip(event_dict.get('src_ip') or event_dict.get('source_ip') or event_dict.get('src'))
    norm_dst_ip = normalize_ip(event_dict.get('dst_ip') or event_dict.get('dest_ip') or event_dict.get('dst'))
    norm_src_port = normalize_port(event_dict.get('src_port') or event_dict.get('source_port') or event_dict.get('sport'))
    norm_dst_port = normalize_port(event_dict.get('dst_port') or event_dict.get('dest_port') or event_dict.get('dport'))
    norm_protocol = normalize_protocol(event_dict.get('protocol') or event_dict.get('proto'))
    norm_severity = normalize_severity(event_dict.get('severity') or event_dict.get('level'))

    event_type = event_dict.get('event_type') or event_dict.get('type') or 'connection'
    category = categorize_event({
        **event_dict,
        'dst_port': norm_dst_port,
        'src_port': norm_src_port,
        'event_type': event_type
    })

    hostname = event_dict.get('hostname') or event_dict.get('host')
    log_source = event_dict.get('log_source') or event_dict.get('source') or 'network_sensor'
    description = event_dict.get('description') or event_dict.get('message') or f"{norm_protocol} traffic {norm_src_ip}:{norm_src_port} -> {norm_dst_ip}:{norm_dst_port}"

    return {
        'dataset_id': event_dict.get('dataset_id', 0),
        'timestamp': norm_timestamp,
        'src_ip': norm_src_ip,
        'dst_ip': norm_dst_ip,
        'src_port': norm_src_port,
        'dst_port': norm_dst_port,
        'protocol': norm_protocol,
        'event_type': str(event_type),
        'event_category': category,
        'hostname': str(hostname) if hostname else None,
        'log_source': str(log_source),
        'description': str(description),
        'severity': norm_severity,
        'raw_data': raw_data_str,
        'normalized': 1
    }
