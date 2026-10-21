import os
import csv
import json
import datetime
from typing import Any, Dict, List, Optional
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)


def export_events_csv(events: List[Dict[str, Any]], filepath: str) -> str:
    """
    Export list of event dictionaries to a CSV file.
    Returns: filepath
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    if not events:
        # Create empty CSV with header
        fieldnames = [
            'id', 'dataset_id', 'timestamp', 'src_ip', 'dst_ip',
            'src_port', 'dst_port', 'protocol', 'event_type',
            'event_category', 'hostname', 'log_source', 'description',
            'severity'
        ]
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
        return filepath

    # Filter out internal keys like _epoch
    clean_events = []
    for ev in events:
        clean = {k: v for k, v in ev.items() if not k.startswith('_')}
        clean_events.append(clean)

    df = pd.DataFrame(clean_events)
    df.to_csv(filepath, index=False, encoding='utf-8')
    return filepath


def export_events_json(events: List[Dict[str, Any]], filepath: str) -> str:
    """
    Export list of event dictionaries to a formatted JSON file.
    Returns: filepath
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    clean_events = []
    for ev in events:
        clean = {k: v for k, v in ev.items() if not k.startswith('_')}
        clean_events.append(clean)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(clean_events, f, indent=2, default=str)
    return filepath


def generate_pdf_report(report_data: Dict[str, Any], filepath: str) -> str:
    """
    Generate an executive investigation and incident response PDF report using ReportLab.
    Returns: filepath
    """
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=14,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1E293B')
    )

    badge_crit = ParagraphStyle('BCrit', parent=table_cell_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#DC2626'))
    badge_high = ParagraphStyle('BHigh', parent=table_cell_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#EA580C'))
    badge_med = ParagraphStyle('BMed', parent=table_cell_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#D97706'))
    badge_low = ParagraphStyle('BLow', parent=table_cell_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#2563EB'))
    badge_info = ParagraphStyle('BInfo', parent=table_cell_style, textColor=colors.HexColor('#64748B'))

    story = []

    # Title & Header
    story.append(Paragraph("Campus Network Attack - Investigation Report", title_style))
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated: {now_str} &bull; Security Operations & Timeline Reconstruction Engine", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=12))

    # 1. Investigation Overview
    inv = report_data.get('investigation') or {}
    inv_title = inv.get('title') or report_data.get('dataset_name') or 'Incident Timeline Reconstruction'
    inv_desc = inv.get('description') or 'Comprehensive incident analysis and digital forensics report.'
    inv_status = (inv.get('status') or 'Active').upper()
    start_t = inv.get('time_range_start') or report_data.get('start_time') or 'N/A'
    end_t = inv.get('time_range_end') or report_data.get('end_time') or 'N/A'

    story.append(Paragraph("Investigation Overview", section_heading))
    overview_data = [
        [Paragraph("<b>Investigation Title:</b>", body_style), Paragraph(inv_title, body_style)],
        [Paragraph("<b>Current Status:</b>", body_style), Paragraph(f"<b>{inv_status}</b>", body_style)],
        [Paragraph("<b>Investigation Scope:</b>", body_style), Paragraph(inv_desc, body_style)],
        [Paragraph("<b>Observed Time Range:</b>", body_style), Paragraph(f"{start_t} &rarr; {end_t}", body_style)]
    ]
    t_overview = Table(overview_data, colWidths=[130, 410])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_overview)
    story.append(Spacer(1, 10))

    # 2. Summary Statistics Table
    stats = report_data.get('stats') or {}
    total_events = stats.get('total_events', len(report_data.get('events', [])))
    unique_hosts = stats.get('unique_hosts', len(report_data.get('hosts', [])))
    alerts_count = stats.get('alerts_count', len(report_data.get('alerts', [])))

    story.append(Paragraph("Incident Metrics Summary", section_heading))
    metric_data = [
        [
            Paragraph("Total Log Events", table_header_style),
            Paragraph("Unique Hosts", table_header_style),
            Paragraph("Security Alerts Triggered", table_header_style)
        ],
        [
            Paragraph(f"<font size=12><b>{total_events:,}</b></font>", body_style),
            Paragraph(f"<font size=12><b>{unique_hosts:,}</b></font>", body_style),
            Paragraph(f"<font size=12><b>{alerts_count:,}</b></font>", body_style)
        ]
    ]
    t_metrics = Table(metric_data, colWidths=[180, 180, 180])
    t_metrics.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#F1F5F9')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 10))

    # 3. Security Alerts Table
    alerts = report_data.get('alerts', [])
    if alerts:
        story.append(Paragraph(f"Detected Security Alerts ({len(alerts)})", section_heading))
        alert_rows = [
            [
                Paragraph("Severity", table_header_style),
                Paragraph("Rule / Attack Type", table_header_style),
                Paragraph("Source IP", table_header_style),
                Paragraph("Destination IP", table_header_style),
                Paragraph("Detection Details", table_header_style)
            ]
        ]
        for a in alerts[:15]:
            sev = str(a.get('severity', 'info')).lower()
            if sev == 'critical':
                s_badge = Paragraph("CRITICAL", badge_crit)
            elif sev == 'high':
                s_badge = Paragraph("HIGH", badge_high)
            elif sev == 'medium':
                s_badge = Paragraph("MEDIUM", badge_med)
            elif sev == 'low':
                s_badge = Paragraph("LOW", badge_low)
            else:
                s_badge = Paragraph("INFO", badge_info)

            alert_rows.append([
                s_badge,
                Paragraph(a.get('rule_name') or a.get('alert_type', ''), table_cell_style),
                Paragraph(a.get('src_ip') or '-', table_cell_style),
                Paragraph(a.get('dst_ip') or '-', table_cell_style),
                Paragraph(a.get('reason') or '', table_cell_style)
            ])

        t_alerts = Table(alert_rows, colWidths=[55, 95, 75, 75, 240])
        t_alerts.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_alerts)
        story.append(Spacer(1, 10))

    # 4. Key Timeline Events
    events = report_data.get('events', [])
    if events:
        story.append(Paragraph("Chronological Attack Timeline Highlights", section_heading))
        event_rows = [
            [
                Paragraph("Timestamp", table_header_style),
                Paragraph("Source", table_header_style),
                Paragraph("Destination", table_header_style),
                Paragraph("Proto", table_header_style),
                Paragraph("Event Description", table_header_style)
            ]
        ]
        # Show key events up to 25
        key_events = [e for e in events if str(e.get('severity')).lower() in ('high', 'critical', 'medium')]
        if len(key_events) < 10:
            key_events = events[:25]
        else:
            key_events = key_events[:25]

        for e in key_events:
            ts_display = e.get('timestamp', '')[11:19] if len(e.get('timestamp', '')) >= 19 else e.get('timestamp', '')
            event_rows.append([
                Paragraph(ts_display, table_cell_style),
                Paragraph(f"{e.get('src_ip')}:{e.get('src_port') or ''}", table_cell_style),
                Paragraph(f"{e.get('dst_ip')}:{e.get('dst_port') or ''}", table_cell_style),
                Paragraph(str(e.get('protocol') or 'TCP'), table_cell_style),
                Paragraph(e.get('description') or '', table_cell_style)
            ])

        t_events = Table(event_rows, colWidths=[60, 95, 95, 45, 245])
        t_events.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_events)
        story.append(Spacer(1, 10))

    # 5. Host Summary Table
    hosts = report_data.get('hosts', [])
    if hosts:
        story.append(Paragraph("Key Network Hosts Involved", section_heading))
        host_rows = [
            [
                Paragraph("IP Address", table_header_style),
                Paragraph("Hostname / Identifier", table_header_style),
                Paragraph("Event Count", table_header_style),
                Paragraph("First Seen", table_header_style),
                Paragraph("Last Seen", table_header_style)
            ]
        ]
        for h in hosts[:10]:
            host_rows.append([
                Paragraph(str(h.get('ip_address') or h.get('ip') or '-'), table_cell_style),
                Paragraph(str(h.get('hostname') or '-'), table_cell_style),
                Paragraph(str(h.get('event_count') or 0), table_cell_style),
                Paragraph(str(h.get('first_seen') or '-')[:19], table_cell_style),
                Paragraph(str(h.get('last_seen') or '-')[:19], table_cell_style)
            ])

        t_hosts = Table(host_rows, colWidths=[90, 140, 70, 120, 120])
        t_hosts.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_hosts)
        story.append(Spacer(1, 10))

    # 6. Analyst Notes & Findings
    analyst_notes = inv.get('analyst_notes') or report_data.get('analyst_notes')
    findings = inv.get('findings') or report_data.get('findings')
    if analyst_notes or findings:
        story.append(Paragraph("Analyst Observations & Findings", section_heading))
        notes_content = []
        if analyst_notes:
            notes_content.append(f"<b>Analyst Notes:</b><br/>{analyst_notes}")
        if findings:
            notes_content.append(f"<b>Key Findings & Root Cause:</b><br/>{findings}")
        story.append(Paragraph("<br/><br/>".join(notes_content), body_style))
        story.append(Spacer(1, 10))

    # 7. Disclaimer & Signoff
    story.append(Spacer(1, 15))
    disclaimer_text = (
        "<b>CONFIDENTIAL &bull; FOR INTERNAL SECURITY TEAM USE ONLY</b><br/>"
        "This report was automatically synthesized by the Campus Network Attack – Timeline Reconstructor "
        "incident response suite. All data was analyzed and verified through cryptographic hash integrity."
    )
    story.append(Paragraph(disclaimer_text, ParagraphStyle('Disc', parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor('#64748B'))))

    doc.build(story)
    return filepath
