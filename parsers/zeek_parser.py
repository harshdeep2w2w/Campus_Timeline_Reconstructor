import os
import re
from typing import Any, Dict, List, Tuple
from engine.normalizer import normalize_event


def parse_zeek_log(filepath: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parse native Zeek (Bro) tab-separated log files with #separator, #fields, #types headers.
    Returns: (records, errors)
    """
    records: List[Dict[str, Any]] = []
    errors: List[str] = []

    if not os.path.exists(filepath):
        errors.append(f"File not found: {filepath}")
        return records, errors

    separator = '\t'
    fields: List[str] = []
    log_path = 'zeek'

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    line_idx = 0
    for line in lines:
        line_idx += 1
        line_str = line.strip('\r\n')
        if not line_str:
            continue

        # Header directives
        if line_str.startswith('#'):
            if line_str.startswith('#separator'):
                parts = line_str.split(None, 1)
                if len(parts) > 1:
                    sep_val = parts[1].strip()
                    # e.g. \x09
                    if sep_val.startswith('\\x'):
                        try:
                            separator = chr(int(sep_val[2:], 16))
                        except Exception:
                            separator = '\t'
                    else:
                        separator = sep_val
            elif line_str.startswith('#path'):
                parts = line_str.split()
                if len(parts) > 1:
                    log_path = parts[1].strip()
            elif line_str.startswith('#fields'):
                parts = line_str.split(separator)
                # The first item is '#fields'
                fields = [f.strip() for f in parts[1:] if f.strip()]
            continue

        # Data rows
        if not fields:
            continue

        parts = line_str.split(separator)
        if len(parts) < len(fields):
            # Try splitting by whitespace if separator split didn't match
            parts = line_str.split()

        if len(parts) != len(fields):
            errors.append(f"Line {line_idx}: field count mismatch ({len(parts)} values for {len(fields)} fields)")
            continue

        row_dict = {}
        for f_name, f_val in zip(fields, parts):
            v = f_val.strip()
            if v in ('-', '(empty)', ''):
                row_dict[f_name] = None
            else:
                row_dict[f_name] = v

        try:
            # Map Zeek specific column names
            event_raw = {
                'timestamp': row_dict.get('ts'),
                'src_ip': row_dict.get('id.orig_h') or row_dict.get('orig_h'),
                'dst_ip': row_dict.get('id.resp_h') or row_dict.get('resp_h'),
                'src_port': row_dict.get('id.orig_p') or row_dict.get('orig_p'),
                'dst_port': row_dict.get('id.resp_p') or row_dict.get('resp_p'),
                'protocol': row_dict.get('proto') or 'TCP',
                'event_type': row_dict.get('service') or row_dict.get('note') or log_path,
                'hostname': row_dict.get('host') or row_dict.get('query') or row_dict.get('server_name'),
                'log_source': f"zeek_{log_path}",
                'raw_data': line_str
            }

            # Generate description based on log_path
            desc = f"Zeek {log_path} log: {event_raw['src_ip']}:{event_raw['src_port']} -> {event_raw['dst_ip']}:{event_raw['dst_port']}"
            if 'query' in row_dict and row_dict['query']:
                desc = f"DNS Query: {row_dict['query']} from {event_raw['src_ip']}"
            elif 'uri' in row_dict and row_dict['uri']:
                desc = f"HTTP {row_dict.get('method', 'REQ')} {row_dict.get('host', '')}{row_dict['uri']}"
            elif 'server_name' in row_dict and row_dict['server_name']:
                desc = f"TLS SNI: {row_dict['server_name']}"

            event_raw['description'] = desc
            normalized = normalize_event(event_raw)
            records.append(normalized)
        except Exception as e:
            errors.append(f"Line {line_idx} normalization error: {str(e)}")

    return records, errors
