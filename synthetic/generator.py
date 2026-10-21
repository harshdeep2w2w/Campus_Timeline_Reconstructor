import json
import random
import datetime
from typing import Any, Dict, List
from database.db import (
    insert_dataset,
    update_dataset,
    insert_events_batch,
    update_hosts,
    insert_alert
)
from engine.detector import detect_suspicious_activity


def generate_sample_data() -> List[Dict[str, Any]]:
    """
    Generate ~400 realistic, clearly labeled synthetic network events representing
    a campus security incident occurring on 2024-10-15 between 08:00:00 and 11:00:00 UTC.
    """
    events: List[Dict[str, Any]] = []
    base_time = datetime.datetime(2024, 10, 15, 8, 0, 0, tzinfo=datetime.timezone.utc)

    # Topology definition
    dns_server = "10.0.2.1"
    dhcp_server = "10.0.2.2"
    web_server = "10.0.2.10"
    mail_server = "10.0.2.20"
    gateway = "10.0.1.1"
    ext_c2 = "203.0.113.50"
    ext_partner = "198.51.100.25"
    admin_hosts = [f"10.0.3.{i}" for i in range(1, 6)]
    student_hosts = [f"10.0.1.{i}" for i in range(10, 51)]

    def _rand_high_port():
        return random.randint(49152, 65530)

    # ------------------------------------------------------------------
    # 1. DHCP assignments (~30 events)
    # ------------------------------------------------------------------
    for i in range(30):
        client_ip = student_hosts[i % len(student_hosts)]
        mac = f"00:1a:2b:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"
        offset_sec = random.randint(60, 1800)
        ts = (base_time + datetime.timedelta(seconds=offset_sec)).isoformat()
        hostname = f"student-device-{i+1}"
        events.append({
            'timestamp': ts,
            'src_ip': dhcp_server,
            'dst_ip': client_ip,
            'src_port': 67,
            'dst_port': 68,
            'protocol': 'UDP',
            'event_type': 'dhcp_ack',
            'event_category': 'DHCP',
            'hostname': hostname,
            'log_source': 'dhcp_server',
            'description': f"DHCP ACK: Assigned {client_ip} to {mac} ({hostname})",
            'severity': 'informational',
            'raw_data': json.dumps({'client_mac': mac, 'assigned_ip': client_ip, 'lease_time': 86400})
        })

    # ------------------------------------------------------------------
    # 2. Normal DNS queries (~80 events)
    # ------------------------------------------------------------------
    legit_domains = [
        "portal.campus.edu", "library.campus.edu", "moodle.campus.edu",
        "canvas.instructure.com", "google.com", "github.com",
        "wikipedia.org", "scholar.google.com", "researchgate.net"
    ]
    for i in range(80):
        client = random.choice(student_hosts)
        domain = random.choice(legit_domains)
        offset_sec = random.randint(300, 10000)
        ts = (base_time + datetime.timedelta(seconds=offset_sec)).isoformat()
        events.append({
            'timestamp': ts,
            'src_ip': client,
            'dst_ip': dns_server,
            'src_port': _rand_high_port(),
            'dst_port': 53,
            'protocol': 'UDP',
            'event_type': 'dns_query',
            'event_category': 'DNS',
            'hostname': domain,
            'log_source': 'zeek_dns',
            'description': f"DNS Standard Query A {domain} from {client}",
            'severity': 'informational',
            'raw_data': json.dumps({'query': domain, 'qtype': 'A', 'rcode': 'NOERROR'})
        })

    # ------------------------------------------------------------------
    # 3. HTTP connections (~80 events)
    # ------------------------------------------------------------------
    endpoints = ["/", "/login", "/courses", "/api/v1/status", "/assets/app.js", "/catalog"]
    for i in range(80):
        client = random.choice(student_hosts)
        dst = web_server if random.random() < 0.7 else ext_partner
        offset_sec = random.randint(600, 10200)
        ts = (base_time + datetime.timedelta(seconds=offset_sec)).isoformat()
        endpoint = random.choice(endpoints)
        events.append({
            'timestamp': ts,
            'src_ip': client,
            'dst_ip': dst,
            'src_port': _rand_high_port(),
            'dst_port': 80,
            'protocol': 'TCP',
            'event_type': 'http_request',
            'event_category': 'HTTP',
            'hostname': 'campus.edu' if dst == web_server else 'partner.edu',
            'log_source': 'zeek_http',
            'description': f"HTTP GET {endpoint} HTTP/1.1 (Status: 200)",
            'severity': 'informational',
            'raw_data': json.dumps({'method': 'GET', 'uri': endpoint, 'status_code': 200})
        })

    # ------------------------------------------------------------------
    # 4. TLS connections (~50 events)
    # ------------------------------------------------------------------
    tls_snis = ["portal.campus.edu", "auth.campus.edu", "cdn.cloudflare.net", "aws.amazon.com"]
    for i in range(50):
        client = random.choice(student_hosts)
        sni = random.choice(tls_snis)
        dst = web_server if "campus" in sni else ext_partner
        offset_sec = random.randint(800, 10500)
        ts = (base_time + datetime.timedelta(seconds=offset_sec)).isoformat()
        events.append({
            'timestamp': ts,
            'src_ip': client,
            'dst_ip': dst,
            'src_port': _rand_high_port(),
            'dst_port': 443,
            'protocol': 'TCP',
            'event_type': 'tls_handshake',
            'event_category': 'TLS/HTTPS',
            'hostname': sni,
            'log_source': 'zeek_ssl',
            'description': f"TLS v1.3 handshake established with SNI: {sni}",
            'severity': 'informational',
            'raw_data': json.dumps({'sni': sni, 'version': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384'})
        })

    # ------------------------------------------------------------------
    # 5. General connections (~60 events)
    # ------------------------------------------------------------------
    for i in range(60):
        src = random.choice(student_hosts)
        proto = random.choice(['TCP', 'UDP'])
        if proto == 'TCP':
            dst = mail_server
            port = 25
            cat = 'SMTP'
            desc = f"SMTP transaction from {src} to {dst}"
        else:
            dst = gateway
            port = 123
            cat = 'Network'
            desc = f"NTP time synchronization with campus gateway {gateway}"

        offset_sec = random.randint(1200, 10600)
        ts = (base_time + datetime.timedelta(seconds=offset_sec)).isoformat()
        events.append({
            'timestamp': ts,
            'src_ip': src,
            'dst_ip': dst,
            'src_port': _rand_high_port(),
            'dst_port': port,
            'protocol': proto,
            'event_type': 'connection',
            'event_category': cat,
            'hostname': None,
            'log_source': 'firewall_log',
            'description': desc,
            'severity': 'informational',
            'raw_data': json.dumps({'direction': 'inbound', 'rule': 'ALLOW_STANDARD_SERVICES'})
        })

    # ------------------------------------------------------------------
    # 6. Suspicious activity from 10.0.1.45 (Compromised Laptop)
    # ------------------------------------------------------------------
    comp_ip = "10.0.1.45"
    comp_start_sec = 3600  # Starts at 09:00:00

    # 6a. Port scanning 10.0.2.10 on ports 21,22,23,25,80,443,3306,5432,8080,8443
    scan_ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]
    for idx, p in enumerate(scan_ports):
        t = (base_time + datetime.timedelta(seconds=comp_start_sec + idx * 2)).isoformat()
        events.append({
            'timestamp': t,
            'src_ip': comp_ip,
            'dst_ip': web_server,
            'src_port': _rand_high_port(),
            'dst_port': p,
            'protocol': 'TCP',
            'event_type': 'port_scan',
            'event_category': 'Reconnaissance',
            'hostname': 'campus-web-srv',
            'log_source': 'suricata_ids',
            'description': f"SYN scan probe to {web_server}:{p} from {comp_ip}",
            'severity': 'high',
            'raw_data': json.dumps({'scan_type': 'SYN', 'flags': 'S', 'target_port': p})
        })

    # 6b. DNS queries to suspicious domains (~10 events)
    c2_domains = ["malware-c2.xyz", "exfil-data.top", "evil-server.tk", "beacon-stage2.buzz"]
    for idx in range(10):
        t = (base_time + datetime.timedelta(seconds=comp_start_sec + 30 + idx * 5)).isoformat()
        domain = c2_domains[idx % len(c2_domains)]
        events.append({
            'timestamp': t,
            'src_ip': comp_ip,
            'dst_ip': dns_server,
            'src_port': _rand_high_port(),
            'dst_port': 53,
            'protocol': 'UDP',
            'event_type': 'dns_query',
            'event_category': 'DNS',
            'hostname': domain,
            'log_source': 'zeek_dns',
            'description': f"DNS Query for suspicious domain {domain} from {comp_ip}",
            'severity': 'high',
            'raw_data': json.dumps({'query': domain, 'answer': ext_c2})
        })

    # 6c. Traffic burst: rapid connections to 203.0.113.50 (~20 events in 2 minutes)
    for idx in range(20):
        t = (base_time + datetime.timedelta(seconds=comp_start_sec + 120 + (idx * 4))).isoformat()
        events.append({
            'timestamp': t,
            'src_ip': comp_ip,
            'dst_ip': ext_c2,
            'src_port': _rand_high_port(),
            'dst_port': 443,
            'protocol': 'TCP',
            'event_type': 'data_exfiltration',
            'event_category': 'Traffic Burst',
            'hostname': 'exfil-data.top',
            'log_source': 'zeek_conn',
            'description': f"High-frequency data upload chunk to {ext_c2} (payload size ~64KB)",
            'severity': 'high',
            'raw_data': json.dumps({'chunk_id': idx, 'bytes_sent': 65536, 'dst_ip': ext_c2})
        })

    # 6d. Connection to unusual port 4444 on external IP
    t_unusual = (base_time + datetime.timedelta(seconds=comp_start_sec + 220)).isoformat()
    events.append({
        'timestamp': t_unusual,
        'src_ip': comp_ip,
        'dst_ip': ext_c2,
        'src_port': _rand_high_port(),
        'dst_port': 4444,
        'protocol': 'TCP',
        'event_type': 'c2_backdoor',
        'event_category': 'Reconnaissance',
        'hostname': 'malware-c2.xyz',
        'log_source': 'zeek_conn',
        'description': f"Metasploit / Reverse shell connection established from {comp_ip} to {ext_c2}:4444",
        'severity': 'critical',
        'raw_data': json.dumps({'alert': 'Backdoor Meterpreter C2 handshake', 'port': 4444})
    })

    # ------------------------------------------------------------------
    # 7. Suspicious activity from 10.0.1.78 (Lateral Movement / Brute-force)
    # ------------------------------------------------------------------
    sec_ip = "10.0.1.78"
    sec_start_sec = 5400  # Starts at 09:30:00

    # 7a. Network sweep connecting to admin hosts on port 445 (~5 events)
    for idx, target in enumerate(admin_hosts):
        t = (base_time + datetime.timedelta(seconds=sec_start_sec + idx * 6)).isoformat()
        events.append({
            'timestamp': t,
            'src_ip': sec_ip,
            'dst_ip': target,
            'src_port': _rand_high_port(),
            'dst_port': 445,
            'protocol': 'TCP',
            'event_type': 'smb_probe',
            'event_category': 'Reconnaissance',
            'hostname': f"admin-srv-{idx+1}",
            'log_source': 'suricata_ids',
            'description': f"SMB port 445 sweep probe from {sec_ip} to {target}",
            'severity': 'high',
            'raw_data': json.dumps({'target_ip': target, 'port': 445, 'probe': 'SMB_NEGOTIATE'})
        })

    # 7b. Repeated SSH attempts to 10.0.2.10 (~15 events)
    for idx in range(15):
        t = (base_time + datetime.timedelta(seconds=sec_start_sec + 60 + idx * 8)).isoformat()
        events.append({
            'timestamp': t,
            'src_ip': sec_ip,
            'dst_ip': web_server,
            'src_port': _rand_high_port(),
            'dst_port': 22,
            'protocol': 'TCP',
            'event_type': 'ssh_bruteforce',
            'event_category': 'SSH',
            'hostname': 'campus-web-srv',
            'log_source': 'auth_log',
            'description': f"Failed SSH password authentication for root/admin from {sec_ip} (Attempt {idx+1}/15)",
            'severity': 'medium',
            'raw_data': json.dumps({'auth_status': 'FAILURE', 'user': 'root', 'attempt': idx + 1})
        })

    # Sort all generated events chronologically
    events.sort(key=lambda e: e['timestamp'])
    return events


def load_sample_data() -> int:
    """
    Create a dataset record, generate synthetic network traffic,
    batch insert records into database, run suspicious activity detector,
    and update host inventory.
    Returns: dataset_id
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    dataset_id = insert_dataset({
        'name': 'Synthetic Campus Network Attack - 2024-10-15',
        'filename': 'synthetic_campus_traffic_oct15.log',
        'file_type': 'synthetic',
        'upload_time': now_iso,
        'record_count': 0,
        'status': 'processing',
        'description': 'Clearly labeled synthetic campus traffic dataset containing student browsing, DNS lookups, lateral scanning, and external C2 exfiltration.'
    })

    # Generate and link dataset_id
    generated = generate_sample_data()
    for ev in generated:
        ev['dataset_id'] = dataset_id

    # Batch insert events
    insert_events_batch(generated)

    # Detect threats and record alerts
    alerts = detect_suspicious_activity(dataset_id=dataset_id)
    for al in alerts:
        insert_alert(al)

    # Update hosts directory
    update_hosts(dataset_id=dataset_id)

    # Finalize dataset status
    update_dataset(dataset_id, {
        'record_count': len(generated),
        'status': 'ready'
    })

    return dataset_id
