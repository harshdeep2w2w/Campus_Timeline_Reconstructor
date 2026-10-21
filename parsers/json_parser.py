import os
import json
from typing import Any, Dict, List, Tuple
from engine.normalizer import normalize_event
from parsers.csv_parser import COLUMN_MAP


def _flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """Recursively flatten nested dictionary keys, e.g. {'id': {'orig_h': '1.2.3.4'}} -> {'id.orig_h': '1.2.3.4'}."""
    items: List[Tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def _extract_canonical_fields(flat_item: Dict[str, Any]) -> Dict[str, Any]:
    """Map flattened keys to canonical event attributes."""
    extracted = {}
    flat_lower = {k.lower(): v for k, v in flat_item.items()}

    # Also handle specific Zeek json keys directly
    zeek_direct = {
        'timestamp': ['ts', 'id.ts', 'timestamp'],
        'src_ip': ['id.orig_h', 'orig_h', 'source_ip', 'src_ip', 'src'],
        'dst_ip': ['id.resp_h', 'resp_h', 'dest_ip', 'dst_ip', 'dst'],
        'src_port': ['id.orig_p', 'orig_p', 'source_port', 'src_port', 'sport'],
        'dst_port': ['id.resp_p', 'resp_p', 'dest_port', 'dst_port', 'dport'],
        'protocol': ['proto', 'protocol'],
        'event_type': ['service', 'event_type', 'type'],
        'hostname': ['host', 'hostname', 'query'],
        'log_source': ['_path', 'log_source', 'source']
    }

    # First check zeek-specific or canonical mappings
    for canonical, candidates in {**COLUMN_MAP, **zeek_direct}.items():
        if canonical in extracted:
            continue
        for cand in candidates:
            cand_lower = cand.lower()
            if cand_lower in flat_lower:
                val = flat_lower[cand_lower]
                if val is not None and val != '-' and val != '(empty)':
                    extracted[canonical] = val
                    break

    return extracted


def parse_json(filepath: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parse JSON or NDJSON (Newline Delimited JSON) file.
    Returns: (records, errors)
    """
    records: List[Dict[str, Any]] = []
    errors: List[str] = []

    if not os.path.exists(filepath):
        errors.append(f"File not found: {filepath}")
        return records, errors

    raw_items = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read().strip()

    if not content:
        errors.append("File is empty.")
        return records, errors

    # Check if whole file is a single JSON array or object
    if content.startswith('[') and content.endswith(']'):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                raw_items = parsed
            else:
                raw_items = [parsed]
        except Exception as e:
            errors.append(f"JSON array parse failed: {str(e)}")
    elif content.startswith('{') and content.endswith('}') and '\n' not in content:
        try:
            raw_items = [json.loads(content)]
        except Exception as e:
            errors.append(f"Single JSON object parse failed: {str(e)}")
    else:
        # Try line by line (NDJSON)
        for line_num, line in enumerate(content.splitlines(), start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                obj = json.loads(line_str)
                if isinstance(obj, dict):
                    raw_items.append(obj)
            except Exception as e:
                errors.append(f"Line {line_num} JSON decode error: {str(e)}")

    if not raw_items and not errors:
        # Fallback: try parsing as generic json
        try:
            data = json.loads(content)
            if isinstance(data, list):
                raw_items = data
            elif isinstance(data, dict):
                raw_items = [data]
        except Exception as e:
            errors.append(f"Generic JSON parsing failed: {str(e)}")

    for idx, item in enumerate(raw_items):
        try:
            if not isinstance(item, dict):
                continue
            flat_item = _flatten_dict(item)
            extracted = _extract_canonical_fields(flat_item)
            # Retain original raw data
            extracted['raw_data'] = json.dumps(item)
            normalized = normalize_event(extracted)
            records.append(normalized)
        except Exception as e:
            errors.append(f"Item {idx + 1} normalization error: {str(e)}")

    return records, errors
