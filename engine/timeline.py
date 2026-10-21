import datetime
from typing import Any, Dict, List, Optional
import dateutil.parser
from database.db import get_event, query_db


def reconstruct_timeline(
    dataset_id: Optional[int] = None,
    filters: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Reconstruct chronological timeline of events matching filters.
    Events are strictly ordered by timestamp ascending.
    """
    filters = dict(filters) if filters else {}
    if dataset_id is not None:
        filters['dataset_id'] = dataset_id

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
        pattern = f"%{filters['search']}%"
        conditions.append("(description LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR hostname LIKE ?)")
        params.extend([pattern, pattern, pattern, pattern])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT * FROM events
        {where_clause}
        ORDER BY timestamp ASC, id ASC
    """
    return query_db(query, params)


def get_event_detail(event_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve single event details and correlate related events
    sharing source or destination IP within a 5-minute (300 seconds) window.
    """
    event = get_event(event_id)
    if not event:
        return None

    # Determine time window
    ts_str = event['timestamp']
    try:
        dt = dateutil.parser.parse(ts_str)
    except Exception:
        dt = datetime.datetime.now(datetime.timezone.utc)

    window_delta = datetime.timedelta(seconds=300)
    start_ts = (dt - window_delta).isoformat()
    end_ts = (dt + window_delta).isoformat()

    ips = [ip for ip in (event.get('src_ip'), event.get('dst_ip')) if ip]

    related_events: List[Dict[str, Any]] = []
    if ips:
        placeholders = ','.join(['?'] * len(ips))
        related_query = f"""
            SELECT * FROM events
            WHERE id != ?
              AND dataset_id = ?
              AND timestamp >= ?
              AND timestamp <= ?
              AND (src_ip IN ({placeholders}) OR dst_ip IN ({placeholders}))
            ORDER BY timestamp ASC
            LIMIT 50
        """
        query_params = [event_id, event['dataset_id'], start_ts, end_ts] + ips + ips
        related_events = query_db(related_query, query_params)

    result = dict(event)
    result['related_events'] = related_events
    return result
