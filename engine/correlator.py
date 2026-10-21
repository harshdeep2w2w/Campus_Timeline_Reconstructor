import datetime
from typing import Any, Dict, List, Optional
import dateutil.parser
from database.db import get_event, query_db, get_settings


def _parse_ts(ts_str: str) -> float:
    """Helper to parse timestamp string to unix epoch seconds."""
    try:
        dt = dateutil.parser.parse(ts_str)
        return dt.timestamp()
    except Exception:
        return 0.0


def correlate_events(dataset_id: Optional[int] = None, time_window: int = 300) -> List[Dict[str, Any]]:
    """
    Correlate events into logical incident groups based on:
    1. 'port_scan' - one source connecting to many different ports on same destination
    2. 'repeated_connection' - same src->dst pair many times
    3. 'traffic_burst' - high volume from one host in short time
    4. 'dns_connection_chain' - DNS query followed by connection to queried IP
    5. 'shared_host' - clustered interactions sharing src/dst IP
    """
    settings = get_settings()
    port_scan_thresh = int(settings.get('port_scan_threshold', 5))
    repeated_thresh = int(settings.get('repeated_connection_threshold', 10))
    burst_thresh = int(settings.get('traffic_burst_threshold', 25))

    where_clause = "WHERE dataset_id = ?" if dataset_id else ""
    params = (dataset_id,) if dataset_id else ()

    events = query_db(
        f"SELECT * FROM events {where_clause} ORDER BY timestamp ASC, id ASC",
        params
    )
    if not events:
        return []

    correlated_groups: List[Dict[str, Any]] = []
    group_counter = 1

    # Attach parsed timestamps
    parsed_events = []
    for ev in events:
        ev_copy = dict(ev)
        ev_copy['_epoch'] = _parse_ts(ev['timestamp'])
        parsed_events.append(ev_copy)

    # ---------------------------------------------------------
    # 1. Port Scan Detection & Grouping
    # ---------------------------------------------------------
    # Group by (src_ip, dst_ip) where distinct dst_ports >= port_scan_thresh within time_window
    pairs: Dict[tuple, List[Dict[str, Any]]] = {}
    for ev in parsed_events:
        src, dst = ev.get('src_ip'), ev.get('dst_ip')
        if src and dst and ev.get('dst_port') is not None:
            pairs.setdefault((src, dst), []).append(ev)

    for (src, dst), ev_list in pairs.items():
        # Sliding window check
        for i in range(len(ev_list)):
            window = [
                e for e in ev_list[i:]
                if e['_epoch'] - ev_list[i]['_epoch'] <= time_window
            ]
            distinct_ports = {e['dst_port'] for e in window if e.get('dst_port')}
            if len(distinct_ports) >= port_scan_thresh:
                # Found port scan group
                # Clean up internal keys
                clean_events = [{k: v for k, v in e.items() if k != '_epoch'} for e in window]
                correlated_groups.append({
                    'group_id': f"GRP-PS-{group_counter}",
                    'events': clean_events,
                    'reason': f"Host {src} scanned {len(distinct_ports)} distinct ports on {dst} within {time_window}s",
                    'correlation_type': 'port_scan'
                })
                group_counter += 1
                break  # Don't duplicate windows for the same pair

    # ---------------------------------------------------------
    # 2. Repeated Connection Detection & Grouping
    # ---------------------------------------------------------
    for (src, dst), ev_list in pairs.items():
        for i in range(len(ev_list)):
            window = [
                e for e in ev_list[i:]
                if e['_epoch'] - ev_list[i]['_epoch'] <= time_window
            ]
            if len(window) >= repeated_thresh:
                clean_events = [{k: v for k, v in e.items() if k != '_epoch'} for e in window]
                correlated_groups.append({
                    'group_id': f"GRP-RC-{group_counter}",
                    'events': clean_events,
                    'reason': f"Host {src} initiated {len(window)} repeated connections to {dst}",
                    'correlation_type': 'repeated_connection'
                })
                group_counter += 1
                break

    # ---------------------------------------------------------
    # 3. Traffic Burst Grouping
    # ---------------------------------------------------------
    src_events_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in parsed_events:
        src = ev.get('src_ip')
        if src:
            src_events_map.setdefault(src, []).append(ev)

    for src, ev_list in src_events_map.items():
        for i in range(len(ev_list)):
            window = [
                e for e in ev_list[i:]
                if e['_epoch'] - ev_list[i]['_epoch'] <= time_window
            ]
            if len(window) >= burst_thresh:
                clean_events = [{k: v for k, v in e.items() if k != '_epoch'} for e in window]
                correlated_groups.append({
                    'group_id': f"GRP-TB-{group_counter}",
                    'events': clean_events,
                    'reason': f"Traffic burst of {len(window)} events generated by {src} within {time_window}s",
                    'correlation_type': 'traffic_burst'
                })
                group_counter += 1
                break

    # ---------------------------------------------------------
    # 4. DNS Connection Chain Grouping
    # ---------------------------------------------------------
    dns_events = [e for e in parsed_events if e.get('event_category') == 'DNS' or e.get('dst_port') == 53]
    for dns_ev in dns_events:
        client_ip = dns_ev.get('src_ip')
        dns_time = dns_ev['_epoch']
        query = (dns_ev.get('hostname') or dns_ev.get('description') or '').lower()

        # Look for subsequent non-DNS connections from client_ip within time_window
        subsequent = [
            e for e in parsed_events
            if e.get('src_ip') == client_ip
            and e.get('event_category') != 'DNS'
            and 0 < (e['_epoch'] - dns_time) <= time_window
        ]
        if subsequent:
            chain = [dns_ev] + subsequent[:5]
            clean_events = [{k: v for k, v in e.items() if k != '_epoch'} for e in chain]
            correlated_groups.append({
                'group_id': f"GRP-DNS-{group_counter}",
                'events': clean_events,
                'reason': f"DNS query ({query}) from {client_ip} followed by {len(subsequent)} outbound connections",
                'correlation_type': 'dns_connection_chain'
            })
            group_counter += 1
            if group_counter > 50:
                break

    # ---------------------------------------------------------
    # 5. Shared Host Grouping (Multi-hop / multi-peer communication)
    # ---------------------------------------------------------
    for src, ev_list in src_events_map.items():
        if len(ev_list) >= 4 and not any(g['reason'].startswith(f"Sequential interactions involving host {src}") for g in correlated_groups):
            distinct_dsts = {e['dst_ip'] for e in ev_list if e.get('dst_ip')}
            if len(distinct_dsts) >= 2:
                sample_events = ev_list[:8]
                clean_events = [{k: v for k, v in e.items() if k != '_epoch'} for e in sample_events]
                correlated_groups.append({
                    'group_id': f"GRP-SH-{group_counter}",
                    'events': clean_events,
                    'reason': f"Sequential interactions involving host {src} communicating with {len(distinct_dsts)} distinct endpoints",
                    'correlation_type': 'shared_host'
                })
                group_counter += 1
                if len(correlated_groups) > 75:
                    break

    return correlated_groups


def find_related_events(event_id: int, time_window: int = 300) -> List[Dict[str, Any]]:
    """
    Given a target event_id, find related events linked by:
    - Shared IP pairs or reverse traffic
    - Temporal proximity (within time_window seconds)
    - DNS correlation or port scanning
    Returns: list of {'event': event_dict, 'reason': str}
    """
    target = get_event(event_id)
    if not target:
        return []

    target_epoch = _parse_ts(target['timestamp'])
    src_ip = target.get('src_ip')
    dst_ip = target.get('dst_ip')
    dataset_id = target.get('dataset_id')

    candidates = query_db(
        """
        SELECT * FROM events
        WHERE id != ? AND dataset_id = ?
        ORDER BY timestamp ASC
        """,
        (event_id, dataset_id)
    )

    related: List[Dict[str, Any]] = []

    for ev in candidates:
        ev_epoch = _parse_ts(ev['timestamp'])
        time_diff = abs(ev_epoch - target_epoch)
        if time_diff > time_window:
            continue

        c_src = ev.get('src_ip')
        c_dst = ev.get('dst_ip')

        # 1. Reverse session traffic
        if c_src == dst_ip and c_dst == src_ip:
            related.append({
                'event': ev,
                'reason': f"Bidirectional response traffic between {src_ip} and {dst_ip} within {int(time_diff)}s"
            })
            continue

        # 2. Identical IP pair
        if c_src == src_ip and c_dst == dst_ip:
            related.append({
                'event': ev,
                'reason': f"Concurrent session from {src_ip} to {dst_ip} ({ev.get('protocol', 'TCP')}/{ev.get('dst_port')})"
            })
            continue

        # 3. DNS lookup prior to this connection
        if target.get('event_category') != 'DNS' and ev.get('event_category') == 'DNS' and c_src == src_ip and ev_epoch <= target_epoch:
            related.append({
                'event': ev,
                'reason': f"DNS query by source host {src_ip} preceding connection by {int(target_epoch - ev_epoch)}s"
            })
            continue

        # 4. Same source host active
        if c_src == src_ip:
            related.append({
                'event': ev,
                'reason': f"Same source host {src_ip} active on network ({ev.get('event_type') or ev.get('event_category')})"
            })
            continue

        # 5. Same destination target host
        if c_dst == dst_ip and dst_ip is not None:
            related.append({
                'event': ev,
                'reason': f"Same destination host {dst_ip} targeted by {c_src}"
            })
            continue

    return related
