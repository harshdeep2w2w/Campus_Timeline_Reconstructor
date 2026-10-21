import os
import pandas as pd
from typing import Any, Dict, List, Tuple
from engine.normalizer import normalize_event


# Mapping variations of column names to canonical schema keys
COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'ts', 'date', 'datetime', 'event_time'],
    'src_ip': ['source_ip', 'src_ip', 'src', 'source', 'orig_h', 'client_ip', 'src_addr'],
    'dst_ip': ['dest_ip', 'dst_ip', 'dst', 'destination', 'dest', 'resp_h', 'server_ip', 'dst_addr'],
    'src_port': ['source_port', 'src_port', 'sport', 'orig_p', 'client_port'],
    'dst_port': ['dest_port', 'dst_port', 'dport', 'resp_p', 'server_port'],
    'protocol': ['protocol', 'proto'],
    'event_type': ['event_type', 'type', 'service', 'action'],
    'event_category': ['event_category', 'category', 'class'],
    'hostname': ['hostname', 'host', 'computer_name', 'device_name'],
    'log_source': ['log_source', 'source_log', 'log', 'sensor', 'source_type'],
    'description': ['description', 'desc', 'message', 'msg', 'info', 'details'],
    'severity': ['severity', 'level', 'sev', 'priority']
}


def _find_matching_column(columns: List[str], candidates: List[str]) -> str:
    """Find the column name in dataframe that matches one of the candidates."""
    cols_lower = {col.lower().strip(): col for col in columns}
    for candidate in candidates:
        if candidate.lower() in cols_lower:
            return cols_lower[candidate.lower()]
    return None


def parse_csv(filepath: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parse a CSV or TSV file into a list of normalized event dictionaries.
    Returns: (records, errors)
    """
    records: List[Dict[str, Any]] = []
    errors: List[str] = []

    if not os.path.exists(filepath):
        errors.append(f"File not found: {filepath}")
        return records, errors

    try:
        # Detect delimiter and load file
        df = None
        for sep in [',', '\t', ';']:
            try:
                df = pd.read_csv(filepath, sep=sep, low_memory=False, nrows=5)
                if len(df.columns) > 1:
                    df = pd.read_csv(filepath, sep=sep, low_memory=False)
                    break
            except Exception:
                continue

        if df is None or df.empty:
            df = pd.read_csv(filepath, sep=None, engine='python')

        if df.empty:
            errors.append("File is empty or contains no parseable records.")
            return records, errors

        # Resolve column mappings
        col_mapping = {}
        for canonical, candidates in COLUMN_MAP.items():
            match = _find_matching_column(list(df.columns), candidates)
            if match:
                col_mapping[canonical] = match

        # Iterate over records
        for idx, row in df.iterrows():
            try:
                raw_dict = row.to_dict()
                clean_row = {}
                for canonical, matched_col in col_mapping.items():
                    val = raw_dict.get(matched_col)
                    if pd.notna(val):
                        clean_row[canonical] = val

                # Keep unmapped fields in raw_dict
                normalized = normalize_event(clean_row)
                records.append(normalized)
            except Exception as e:
                errors.append(f"Row {idx + 1} parse error: {str(e)}")

    except Exception as e:
        errors.append(f"Failed to read CSV file: {str(e)}")

    return records, errors
