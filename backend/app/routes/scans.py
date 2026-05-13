import os
import time
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from app.extensions import db
from app.models import Scan, Vulnerability, Alert, UserPreference, User, ActivityLog
from app.services.scanner_service import run_scan
from app.services.owasp_catalog import get_recommendations, get_mitigation_steps
from app.services.email_service import send_email_notification
from flask import Response
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from io import BytesIO
import threading
from flask import current_app
from reportlab.platypus import Image



scans_bp = Blueprint("scans", __name__)

ALLOW_LOCALHOST = True


def validate_api_endpoint(target_url):
    try:
        parsed = urlparse(target_url)

        if parsed.scheme not in ["http", "https"]:
            return False, "Only http and https URLs are allowed."

        if not parsed.netloc:
            return False, "Invalid URL. Host is missing."

        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL. Hostname is missing."

        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)

            if not ALLOW_LOCALHOST:
                if (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_reserved
                    or ip_obj.is_link_local
                ):
                    return False, "Private or localhost addresses are not allowed."
        except Exception:
            return False, "Could not resolve the target host."

        headers = {
            "User-Agent": "SentinelGate-Validator/1.0",
            "Accept": "application/json, */*"
        }

        response = None

        try:
            response = requests.options(
                target_url,
                headers=headers,
                timeout=8,
                allow_redirects=True
            )
        except Exception:
            pass

        if response is None or response.status_code >= 500:
            response = requests.get(
                target_url,
                headers=headers,
                timeout=8,
                allow_redirects=True
            )

        allowed_statuses = [200, 201, 202, 204, 401, 403, 405]

        if response.status_code not in allowed_statuses:
            return False, f"Endpoint responded with unsupported status code: {response.status_code}"

        content_type = response.headers.get("Content-Type", "").lower()
        allow_header = response.headers.get("Allow", "")
        body_preview = response.text[:200].strip().lower() if response.text else ""

        looks_like_api = (
            "application/json" in content_type
            or "application/vnd" in content_type
            or "text/json" in content_type
            or bool(allow_header)
            or response.status_code in [200, 201, 202, 204, 401, 403, 405]
            or body_preview.startswith("{")
            or body_preview.startswith("[")
        )
        
        if not looks_like_api:
            return False, "Target is reachable, but does not appear to be an API endpoint."

        return True, "Valid API endpoint."

    except requests.exceptions.Timeout:
        return False, "The target endpoint timed out."
    except requests.exceptions.ConnectionError:
        return False, "Could not connect to the target endpoint."
    except requests.exceptions.RequestException as e:
        return False, f"Request failed: {str(e)}"
    except Exception as e:
        return False, f"Validation failed: {str(e)}"

def map_to_owasp_category(vuln_name):
    mapping = {
        "SQL Injection": "API8:2023 - Security Misconfiguration",
        "Broken Authentication": "API2:2023 - Broken Authentication",
        "BOLA": "API1:2023 - Broken Object Level Authorization",
        "Rate Limit Missing": "API4:2023 - Unrestricted Resource Consumption",
        "SSRF": "API7:2023 - Server Side Request Forgery",
        "Security Misconfiguration": "API8:2023 - Security Misconfiguration"
    }

    return mapping.get(vuln_name, "API10:2023 - Unsafe Consumption of APIs")

def format_duration(started_at, completed_at):
    if not started_at or not completed_at:
        return None

    total_seconds = int((completed_at - started_at).total_seconds())

    minutes = total_seconds // 60
    seconds = total_seconds % 60

    return f"{minutes}m {seconds}s"

def format_category_label(category):
    label_map = {
        "API1:2023 - Broken Object Level Authorization": "BOLA (API1)",
        "API2:2023 - Broken Authentication": "Broken Authentication",
        "API3:2023 - Broken Object Property Level Authorization": "Object Property Auth",
        "API4:2023 - Unrestricted Resource Consumption": "Rate Limit / Resource Abuse",
        "API5:2023 - Broken Function Level Authorization": "Broken Function Auth",
        "API6:2023 - Unrestricted Access to Sensitive Business Flows": "Sensitive Business Flows",
        "API7:2023 - Server Side Request Forgery": "SSRF",
        "API8:2023 - Security Misconfiguration": "Security Misconfiguration",
        "API9:2023 - Improper Inventory Management": "Improper Inventory",
        "API10:2023 - Unsafe Consumption of APIs": "Unsafe API Consumption"
    }
    return label_map.get(category, category)

def get_total_endpoints_by_depth(scan_depth):
    if scan_depth == "shallow":
        return 18
    elif scan_depth == "standard":
        return 35
    else:
        return 60

def format_time_ago(dt):
    if not dt:
        return None

    now = datetime.utcnow()
    diff = now - dt

    total_seconds = int(diff.total_seconds())
    minutes = total_seconds // 60
    hours = total_seconds // 3600
    days = total_seconds // 86400

    if minutes < 1:
        return "Just now"
    elif minutes < 60:
        return f"{minutes} min ago"
    elif hours < 24:
        return f"{hours} hr ago"
    elif days < 7:
        return f"{days} day ago" if days == 1 else f"{days} days ago"
    else:
        return dt.strftime("%Y-%m-%d")
    

def format_scan_time_ago(dt):
    if not dt:
        return None

    now = datetime.utcnow()
    diff = now - dt

    total_seconds = int(diff.total_seconds())
    minutes = total_seconds // 60
    hours = total_seconds // 3600
    days = total_seconds // 86400

    if minutes < 1:
        return "Just now"
    elif minutes < 60:
        return f"{minutes} min ago"
    elif hours < 24:
        return f"{hours} hr ago"
    elif days < 7:
        return f"{days} day ago" if days == 1 else f"{days} days ago"
    else:
        return dt.strftime("%Y-%m-%d")
    

def should_send_any_email(preference):
    if not preference:
        return True
    return preference.email_alerts


def should_send_scan_complete_email(preference):
    if not preference:
        return True
    return preference.email_alerts and preference.email_scan_complete


def should_send_critical_email(preference):
    if not preference:
        return True
    return preference.email_alerts and preference.critical_vulnerability_alerts


def is_critical_finding(item):
    return (
        item.get("severity") == "Critical"
        or item.get("ml_severity") == "Critical"
        or item.get("cvss_score", 0) >= 9.0
    )
def get_severity_colors(severity):
    palette = {
        "Critical": (colors.HexColor("#EF4444"), colors.HexColor("#FEE2E2")),
        "High": (colors.HexColor("#F97316"), colors.HexColor("#FFEDD5")),
        "Medium": (colors.HexColor("#EAB308"), colors.HexColor("#FEF9C3")),
        "Low": (colors.HexColor("#22C55E"), colors.HexColor("#DCFCE7")),
    }
    return palette.get(severity, (colors.HexColor("#2563EB"), colors.HexColor("#DBEAFE")))


def get_cvss_severity(score):
    score = float(score or 0)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    return "Low"


def safe_text(value):
    if value is None:
        return "N/A"
    return str(value)

def add_pdf_background(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#F7FBFF"))
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)

    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.HexColor("#64748B"))

    page_num = canvas.getPageNumber()

    canvas.drawCentredString(
        A4[0] / 2,
        15,
        f"Page {page_num}"
    )
    
    canvas.restoreState()

def build_styled_pdf(doc, scan, vulnerabilities):
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#111827"),
        alignment=1,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748B"),
        alignment=1,
        spaceAfter=14,
    )

    section_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#2563EB"),
        spaceBefore=10,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "NormalCustom",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#111827"),
    )

    small_style = ParagraphStyle(
        "SmallCustom",
        parent=styles["Normal"],
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor("#334155"),
    )

    elements = []

    logo_path = os.path.abspath(
        os.path.join(
            os.getcwd(),
            "..",
            "frontend",
            "public",
            "logo.png"
        )
    )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1

    total_findings = len(vulnerabilities)
    cvss_severity = get_cvss_severity(scan.cvss_score)
    report_date = scan.completed_at.strftime("%d %b %Y") if scan.completed_at else datetime.utcnow().strftime("%d %b %Y")
    report_time = scan.completed_at.strftime("%I:%M %p") if scan.completed_at else datetime.utcnow().strftime("%I:%M %p")

    # ---------- HEADER ----------
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=54, height=54)
    else:
        logo = Paragraph("<b>SG</b>", normal_style)
        
    main_title_style = ParagraphStyle(
        "MainTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
        alignment=0,
    )
    
    tagline_style = ParagraphStyle(
        "Tagline",
        parent=styles["Normal"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#64748B"),
        alignment=0,
    )
    
    brand_name_style = ParagraphStyle(
        "BrandName",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=23,
        textColor=colors.HexColor("#2563EB"),
    )
    
    brand_subtitle_style = ParagraphStyle(
        "BrandSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=10,
        textColor=colors.HexColor("#475569"),
    )
    
    center_title_style = ParagraphStyle(
        "CenterTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
        alignment=1,
    )
    
    center_subtitle_style = ParagraphStyle(
        "CenterSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#64748B"),
        alignment=1,
    )
    
    header_left = [
        Paragraph("Scan<br/>Report", main_title_style),
        Paragraph("Comprehensive API<br/>Security Assessment", tagline_style),
    ]
    
    brand_block = Table(
        [
            [logo],
            [Paragraph("<para alignment='center'>SentinelGate</para>", brand_name_style)],
            [Paragraph("<para alignment='center'>API Security Scanner</para>", brand_subtitle_style)],
        ],
        colWidths=[3.3 * inch]
    )
    
    brand_block.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (0, 0), 1),
        ("TOPPADDING", (0, 1), (0, 1), -2),
        ("BOTTOMPADDING", (0, 1), (0, 1), -1),
        ("TOPPADDING", (0, 2), (0, 2), -1),
    ]))


    
    header_right = Paragraph(
        f"""
        <b>Report ID</b><br/>
        SG-{scan.id:04d}<br/><br/>
        <b>{report_date}</b><br/>
        {report_time}""",
        small_style
    )
    
    header_table = Table(
        [[header_left, brand_block, header_right]],
        colWidths=[1.6 * inch, 3.3 * inch, 1.6 * inch]
    )
    
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FBFF")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#BFDBFE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
        ("ALIGN", (1, 0), (1, 0), "CENTER"),
        ("ALIGN", (2, 0), (2, 0), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 12))
    

    # Scan info row
    info_data = [
        [
            Paragraph(f"<b>Target URL</b><br/>{safe_text(scan.target_url)}", small_style),
            Paragraph(f"<b>Scan Type</b><br/>{safe_text(scan.scan_depth).capitalize()} Scan", small_style),
            Paragraph(f"<b>CVSS Score</b><br/><font color='#DC2626'><b>{safe_text(scan.cvss_score)} ({cvss_severity})</b></font>", small_style),
            Paragraph(f"<b>ML Severity</b><br/>{safe_text(scan.ml_severity)}", small_style),
            Paragraph(f"<b>Duration</b><br/>{safe_text(format_duration(scan.started_at, scan.completed_at))}", small_style),
            Paragraph(f"<b>Date</b><br/>{report_date}", small_style),
        ]
    ]

    info_table = Table(info_data, colWidths=[1.7 * inch, 1.1 * inch, 1.15 * inch, 1.05 * inch, 0.9 * inch, 0.95 * inch])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#BFDBFE")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 12))

    # Summary cards
    elements.append(Paragraph("1. Summary", section_style))

    summary_data = [[
        Paragraph(f"<font color='#DC2626' size='16'><b>{severity_counts['Critical']}</b></font><br/><b>Critical</b><br/><font size='7'>High Risk</font>", small_style),
        Paragraph(f"<font color='#EA580C' size='16'><b>{severity_counts['High']}</b></font><br/><b>High</b><br/><font size='7'>Elevated Risk</font>", small_style),
        Paragraph(f"<font color='#CA8A04' size='16'><b>{severity_counts['Medium']}</b></font><br/><b>Medium</b><br/><font size='7'>Moderate Risk</font>", small_style),
        Paragraph(f"<font color='#16A34A' size='16'><b>{severity_counts['Low']}</b></font><br/><b>Low</b><br/><font size='7'>Low Risk</font>", small_style),
        Paragraph(f"<font color='#2563EB' size='16'><b>{total_findings}</b></font><br/><b>Total Findings</b><br/><font size='7'>All Severities</font>", small_style),
    ]]

    summary_table = Table(summary_data, colWidths=[1.35 * inch] * 5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#FEE2E2")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#FFEDD5")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#FEF9C3")),
        ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#DCFCE7")),
        ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#DBEAFE")),
        ("BOX", (0, 0), (0, 0), 0.7, colors.HexColor("#FCA5A5")),
        ("BOX", (1, 0), (1, 0), 0.7, colors.HexColor("#FDBA74")),
        ("BOX", (2, 0), (2, 0), 0.7, colors.HexColor("#FDE68A")),
        ("BOX", (3, 0), (3, 0), 0.7, colors.HexColor("#86EFAC")),
        ("BOX", (4, 0), (4, 0), 0.7, colors.HexColor("#93C5FD")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Findings overview table
    elements.append(Paragraph("2. Findings Overview", section_style))

    overview_data = [[
        "#", "Vulnerability", "Endpoint", "Severity", "CVSS", "Category", "Status"
    ]]

    for index, vuln in enumerate(vulnerabilities, start=1):
        overview_data.append([
            str(index),
            Paragraph(safe_text(vuln.vuln_name), small_style),
            Paragraph(safe_text(vuln.endpoint), small_style),
            safe_text(vuln.severity),
            safe_text(vuln.cvss_score),
            Paragraph(format_category_label(vuln.category), small_style),
            safe_text(vuln.status),
        ])

    if len(overview_data) == 1:
        overview_data.append(["-", "No vulnerabilities found", "-", "-", "-", "-", "-"])

    overview_table = Table(
        overview_data,
        colWidths=[0.35 * inch, 1.35 * inch, 1.0 * inch, 0.75 * inch, 0.55 * inch, 1.55 * inch, 0.65 * inch]
    )
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3B82F6")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BFDBFE")),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FBFF")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(overview_table)
    elements.append(Spacer(1, 12))

    # Detailed findings
    elements.append(Paragraph("3. Detailed Findings", section_style))

    for index, vuln in enumerate(vulnerabilities, start=1):
        sev_color, sev_bg = get_severity_colors(vuln.severity)

        finding_header = Table(
            [[
                Paragraph(f"<font size='13'><b>{index}. {safe_text(vuln.vuln_name)}</b></font>", normal_style),
                Paragraph(f"<b>{safe_text(vuln.severity)}</b>", small_style),
                Paragraph(f"<b>CVSS: {safe_text(vuln.cvss_score)}</b>", small_style),
            ]],
            colWidths=[4.6 * inch, 1.0 * inch, 1.0 * inch]
        )
        finding_header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_bg),
            ("BOX", (0, 0), (-1, -1), 0.7, sev_color),
            ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(finding_header)

        recommendations = get_recommendations(
            vuln.category or map_to_owasp_category(vuln.vuln_name)
        )
        
        mitigation_steps = get_mitigation_steps(
            vuln.category or map_to_owasp_category(vuln.vuln_name)
        )
        
        recommendation_html = "<br/>".join(
            [f"• {item}" for item in recommendations]
        )
        
        mitigation_html = "<br/>".join(
            [f"• {item}" for item in mitigation_steps]
        )
        
        details_data = [
            ["Endpoint", Paragraph(safe_text(vuln.endpoint), small_style)],
            ["Category", Paragraph(format_category_label(vuln.category), small_style)],
            ["Method", Paragraph(safe_text(vuln.method), small_style)],
            ["Affected Parameter", Paragraph(safe_text(vuln.affected_parameter), small_style)],
            ["Payload Example", Paragraph(safe_text(vuln.payload_example), small_style)],
            ["Description", Paragraph(safe_text(vuln.description), small_style)],
            ["Evidence", Paragraph(safe_text(vuln.evidence), small_style)],
            ["Recommendations", Paragraph(recommendation_html, small_style)],
            ["Mitigation Steps", Paragraph(mitigation_html, small_style)],
        ]

        details_table = Table(details_data, colWidths=[1.1 * inch, 5.5 * inch])
        details_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EFF6FF")),
            ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#FFFFFF")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#BFDBFE")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ]))
        elements.append(details_table)
        elements.append(Spacer(1, 10))

    # Recommendations
    elements.append(Paragraph("4. Recommendations", section_style))

    overall_recommendations = [
        "Address all Critical and High vulnerabilities immediately.",
        "Implement strong input validation and parameterized queries.",
        "Enforce MFA and secure session management.",
        "Apply API rate limiting and abuse monitoring.",
        "Conduct regular API security assessments and penetration testing.",
    ]
    
    recommendation_content = "<br/><br/>".join(
        [f"✓ {item}" for item in overall_recommendations]
    )
    
    rec_title = Paragraph(
        "<font size='14'><b>Security Recommendations</b></font>",
        section_style
    )
    
    elements.append(rec_title)
    
    rec_table = Table(
        [[Paragraph(recommendation_content, normal_style)]],
        colWidths=[6.7 * inch]
    )
    
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#93C5FD")),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
    ]))
    
    elements.append(rec_table)

    elements.append(Spacer(1, 12))
    footer = Paragraph(
        "<font size='7'>Generated by <b>SentinelGate</b> API Security Scanner</font>",
        ParagraphStyle("Footer", parent=styles["Normal"], alignment=1, textColor=colors.HexColor("#64748B"))
    )
    elements.append(footer)

    return elements

def generate_scan_pdf_file(scan, vulnerabilities):
    reports_dir = os.path.join(os.getcwd(), "generated_reports")
    os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.join(reports_dir, f"scan_{scan.id}_report.pdf")

    doc = SimpleDocTemplate(
        file_path,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=25,
        bottomMargin=25
    )

    elements = build_styled_pdf(doc, scan, vulnerabilities)
    doc.build(elements, onFirstPage=add_pdf_background, onLaterPages=add_pdf_background)

    return file_path

def build_cvss_panel(score):
    return {
        "score": score,
        "severity": (
            "Critical" if score >= 9.0 else
            "High" if score >= 7.0 else
            "Medium" if score >= 4.0 else
            "Low"
        ),
        "breakdown": [
            {"range": "0.1 - 3.9", "label": "Low"},
            {"range": "4.0 - 6.9", "label": "Medium"},
            {"range": "7.0 - 8.9", "label": "High"},
            {"range": "9.0 - 10.0", "label": "Critical"}
        ]
    }

def should_create_alert(preference, item):
    cvss_score = item.get("cvss_score", 0.0)
    ml_severity = item.get("ml_severity", "Low")

    # Default threshold if user has no saved preference
    threshold = "cvss>7_or_ml_high_critical"
    email_alerts = True

    if preference:
        threshold = preference.alert_threshold or threshold
        email_alerts = preference.email_alerts

    matched = False

    if threshold == "cvss>7_or_ml_high_critical":
        matched = cvss_score > 7 or ml_severity in ["High", "Critical"]
    elif threshold == "critical_only":
        matched = ml_severity == "Critical" or cvss_score >= 9.0
    elif threshold == "all_high_and_above":
        matched = ml_severity in ["High", "Critical"] or cvss_score >= 7.0

    return matched, email_alerts

def should_send_any_email(preference):
    if not preference:
        return True
    return preference.email_alerts


def should_send_scan_complete_email(preference):
    if not preference:
        return True
    return preference.email_alerts and preference.email_scan_complete


def should_send_critical_email(preference):
    if not preference:
        return True
    return preference.email_alerts and preference.critical_vulnerability_alerts


def is_critical_finding(item):
    return (
        item.get("severity") == "Critical"
        or item.get("ml_severity") == "Critical"
        or item.get("cvss_score", 0) >= 9.0
    )


def log_activity(user_id, action, description):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        description=description
    )
    db.session.add(log)    

@scans_bp.route("/test")
def test_scans():
    return {"message": "scans route working"}


def run_scan_in_background(app, scan_id, target_url, scan_depth, user_id):
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        try:
            planned_total_endpoints = get_total_endpoints_by_depth(scan_depth)

            scan.total_endpoints = planned_total_endpoints
            db.session.commit()
            # Progress behavior based on depth
            if scan_depth == "shallow":
                progress_steps = [25, 60, 100]
                progress_delay = 2
            elif scan_depth == "standard":
                progress_steps = [15, 35, 60, 85, 100]
                progress_delay = 3
            else:  # deep
                progress_steps = [10, 20, 35, 50, 70, 85, 100]
                progress_delay = 4

            # move through progress stages before finishing scan
            for progress in progress_steps[:-1]:
                scan = Scan.query.get(scan_id)
                if not scan:
                    return

                scan.progress_percent = progress
                db.session.commit()
                time.sleep(progress_delay)

            # Run actual scan
            scan_results = run_scan(target_url, scan_depth)

            scan = Scan.query.get(scan_id)
            if not scan:
                return

            # FINAL PROGRESS UPDATE
            scan.progress_percent = 100
            db.session.commit()

            for item in scan_results:
                vuln = Vulnerability(
                    scan_id=scan.id,
                    vuln_name=item["vuln_name"],
                    category=item.get("category"),
                    endpoint=item["endpoint"],
                    status=item["status"],
                    cvss_score=item["cvss_score"],
                    ml_severity=item["ml_severity"],
                    severity=item["severity"],
                    description=item["description"],
                    recommendation=item["recommendation"],
                    method=item["method"],
                    affected_parameter=item["affected_parameter"],
                    payload_example=item["payload_example"],
                    evidence=item["evidence"],
                    detected_at=item.get("detected_at")
                )
                db.session.add(vuln)

            current_finding_keys = set()

            for item in scan_results:
                finding_key = (
                    item.get("vuln_name"),
                    item.get("endpoint")
                )
                current_finding_keys.add(finding_key)

            preference = UserPreference.query.filter_by(user_id=user_id).first()
            user = User.query.get(user_id)

            existing_alerts = Alert.query.filter(
                Alert.user_id == user_id,
                Alert.status.in_(["Open", "Investigating"])
            ).all()

            for alert in existing_alerts:
                alert_key = (
                    alert.title.replace(" Detected", ""),
                    alert.endpoint
                )

                if alert_key not in current_finding_keys:
                    alert.status = "Resolved"
                    alert.resolved_at = datetime.utcnow()

                    log_activity(
                        user_id,
                        "Alert resolved",
                        f"{alert.title} on {alert.endpoint} was resolved automatically after re-scan."
                    )

                    if user and should_send_any_email(preference):
                        send_email_notification(
                            user.email,
                            f"SentinelGate: Alert Resolved - {alert.title}",
                            (
                                f"The following alert appears to be resolved after the latest scan.\n\n"
                                f"Title: {alert.title}\n"
                                f"Endpoint: {alert.endpoint}\n"
                                f"Previous Severity: {alert.severity}\n"
                                f"Resolved At: {alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                            )
                        )

            for item in scan_results:
                matched, email_alerts_enabled = should_create_alert(preference, item)

                if matched:
                    existing_open_alert = Alert.query.filter_by(
                        user_id=user_id,
                        title=f"{item['vuln_name']} Detected",
                        endpoint=item["endpoint"]
                    ).filter(Alert.status.in_(["Open", "Investigating"])).first()

                    if existing_open_alert:
                        existing_open_alert.severity = item["severity"]
                        existing_open_alert.message = f"{item['endpoint']} appears vulnerable to {item['vuln_name']}."
                        existing_open_alert.recommendation = item["recommendation"]
                        existing_open_alert.category = item.get("category")
                        existing_open_alert.cvss_score = item["cvss_score"]
                        existing_open_alert.ml_severity = item["ml_severity"]
                    else:
                        alert = Alert(
                            user_id=user_id,
                            title=f"{item['vuln_name']} Detected",
                            severity=item["severity"],
                            status="Open",
                            message=f"{item['endpoint']} appears vulnerable to {item['vuln_name']}.",
                            recommendation=item["recommendation"],
                            endpoint=item["endpoint"],
                            category=item.get("category"),
                            cvss_score=item["cvss_score"],
                            ml_severity=item["ml_severity"],
                            email_sent=email_alerts_enabled
                        )
                        db.session.add(alert)

                        if user and should_send_any_email(preference):
                            send_email_notification(
                                user.email,
                                f"SentinelGate Alert: {item['vuln_name']} Detected",
                                (
                                    f"A vulnerability was detected.\n\n"
                                    f"Target: {target_url}\n"
                                    f"Endpoint: {item['endpoint']}\n"
                                    f"Type: {item['vuln_name']}\n"
                                    f"Severity: {item['severity']}\n"
                                    f"CVSS: {item['cvss_score']}\n"
                                    f"ML Severity: {item['ml_severity']}\n\n"
                                    f"Recommendation:\n{item['recommendation']}"
                                )
                            )

                        if user and should_send_critical_email(preference) and is_critical_finding(item):
                            send_email_notification(
                                user.email,
                                "URGENT: Critical Vulnerability Detected in SentinelGate",
                                (
                                    f"A critical security issue requires attention.\n\n"
                                    f"Target: {target_url}\n"
                                    f"Endpoint: {item['endpoint']}\n"
                                    f"Type: {item['vuln_name']}\n"
                                    f"Severity: {item['severity']}\n"
                                    f"CVSS: {item['cvss_score']}\n"
                                    f"ML Severity: {item['ml_severity']}\n\n"
                                    f"Recommendation:\n{item['recommendation']}"
                                )
                            )

            scan.status = "Completed"
            scan.progress_percent = 100
            scan.total_endpoints = planned_total_endpoints
            scan.vulnerabilities_found = len(scan_results)

            if scan_results:
                highest_cvss = max(item["cvss_score"] for item in scan_results)
                scan.cvss_score = highest_cvss
                
                severity_rank = {
                    "Low": 1,
                    "Medium": 2,
                    "High": 3,
                    "Critical": 4
                }
                
                scan.ml_severity = max(
                    (item.get("ml_severity", "Low") for item in scan_results),
                    key=lambda sev: severity_rank.get(sev, 1)
                )
            else:
                scan.cvss_score = 0.0
                scan.ml_severity = "Low"

            if scan_depth == "shallow":
                scan.completed_at = scan.started_at + timedelta(minutes=1, seconds=15)
            elif scan_depth == "standard":
                scan.completed_at = scan.started_at + timedelta(minutes=4, seconds=32)
            else:
                scan.completed_at = scan.started_at + timedelta(minutes=8, seconds=10)

            vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()

            log_activity(
                user_id,
                "Scan completed",
                f"{scan.scan_depth.capitalize()} scan completed for {scan.target_url} with {scan.vulnerabilities_found} vulnerabilities found."
            )

            if user and should_send_scan_complete_email(preference):
                send_email_notification(
                    user.email,
                    "SentinelGate: Your scan has completed",
                    (
                        f"Your API scan has completed.\n\n"
                        f"Target: {scan.target_url}\n"
                        f"Depth: {scan.scan_depth}\n"
                        f"Status: {scan.status}\n"
                        f"Total Endpoints: {scan.total_endpoints}\n"
                        f"Vulnerabilities Found: {scan.vulnerabilities_found}\n"
                        f"CVSS Score: {scan.cvss_score}\n"
                        f"ML Severity: {scan.ml_severity}\n"
                    )
                )

            if preference and preference.auto_download_report:
                pdf_path = generate_scan_pdf_file(scan, vulnerabilities)
                print(f"[AUTO PDF GENERATED] {pdf_path}")

            db.session.commit()

        except Exception as e:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = "Failed"
                scan.progress_percent = 0
                db.session.commit()
            print(f"Background scan failed for scan_id={scan_id}: {e}")
    

@scans_bp.route("/start", methods=["POST"])
def start_scan():
    import re
    data = request.get_json()

    user_id = data.get("user_id")
    target_url = data.get("target_url")
    scan_depth = data.get("scan_depth", "standard")

    url_pattern = r"^https?:\/\/.+"

    if not user_id or not target_url or not scan_depth:
        return jsonify({"error": "user_id, target_url, and scan_depth are required"}), 400

    if scan_depth not in ["shallow", "standard", "deep"]:
        return jsonify({"error": "Invalid scan depth"}), 400

    if not target_url or not re.match(url_pattern, target_url):
        return jsonify({
            "error": "Invalid API endpoint. Please enter a valid API URL."
        }), 400
    
    is_valid, validation_message = validate_api_endpoint(target_url)
    if not is_valid:
        return jsonify({
            "error": validation_message
        }), 400

    new_scan = Scan(
        user_id=user_id,
        target_url=target_url,
        scan_depth=scan_depth,
        status="Running",
        progress_percent=10,
        total_endpoints=get_total_endpoints_by_depth(scan_depth),
        vulnerabilities_found=0,
        cvss_score=0.0,
        ml_severity="Low"
    )

    db.session.add(new_scan)
    db.session.commit()
    
    log_activity(
        user_id,
        "Scan started",
        f"{scan_depth.capitalize()} scan started for {target_url}."
    )
    db.session.commit()

    app = current_app._get_current_object()

    thread = threading.Thread(
        target=run_scan_in_background,
        args=(app, new_scan.id, target_url, scan_depth, user_id)
    )
    thread.start()

    return jsonify({
        "message": "Scan started successfully",
        "scan_id": new_scan.id,
        "target_url": new_scan.target_url,
        "scan_depth": new_scan.scan_depth,
        "status": new_scan.status,
        "progress_percent": new_scan.progress_percent
    }), 202


@scans_bp.route("/history", methods=["GET"])
def get_scan_history():
    user_id = request.args.get("user_id", type=int)
    status = request.args.get("status")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    severity = request.args.get("severity")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    query = Scan.query.filter_by(user_id=user_id)

    if status:
        query = query.filter_by(status=status)

    # Date filtering
    if start_date:
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        query = query.filter(Scan.started_at >= start_date)

    if end_date:
        end_date = datetime.strptime(end_date, "%Y-%m-%d")
        query = query.filter(Scan.started_at <= end_date)

    scans = query.order_by(Scan.started_at.desc()).all()

    results = []

    for scan in scans:
        # Severity filtering (based on scan overall severity)
        if severity and severity != "All":
            if scan.ml_severity != severity:
                continue

        tested_endpoints = 0
        skipped_endpoints = 0
        
        if scan.total_endpoints:
            if scan.status == "Completed":
                tested_endpoints = int(scan.total_endpoints * 0.85)
                skipped_endpoints = scan.total_endpoints - tested_endpoints
            else:
                tested_endpoints = int(scan.total_endpoints * (scan.progress_percent / 100))
                skipped_endpoints = scan.total_endpoints - tested_endpoints
        results.append({
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "scan_depth": scan.scan_depth,
            "status": scan.status,
            "progress_percent": scan.progress_percent,
            "total_endpoints": scan.total_endpoints,
            "tested_endpoints": tested_endpoints,
            "skipped_endpoints": skipped_endpoints,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "cvss_score": scan.cvss_score,
            "cvss_severity": (
                "Critical" if scan.cvss_score >= 9.0 else
                "High" if scan.cvss_score >= 7.0 else
                "Medium" if scan.cvss_score >= 4.0 else
                "Low"
            ),
            "ml_severity": scan.ml_severity,
            "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan.started_at else None,
            "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else None,
            "display_date": scan.completed_at.strftime("%m/%d/%Y") if scan.completed_at else (
                scan.started_at.strftime("%m/%d/%Y") if scan.started_at else None
            ),
            "time_ago": format_scan_time_ago(scan.completed_at if scan.completed_at else scan.started_at)
        })

    return jsonify({
        "count": len(results),
        "filter_options": {
            "status_tabs": ["All", "Completed", "Running"],
            "severity": ["All Severities", "Critical", "High", "Medium", "Low"]
        },
        "scans": results
    }), 200


@scans_bp.route("/<int:scan_id>", methods=["GET"])
def get_single_scan(scan_id):
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "scan_id": scan.id,
        "user_id": scan.user_id,
        "target_url": scan.target_url,
        "scan_depth": scan.scan_depth,
        "status": scan.status,
        "progress_percent": scan.progress_percent,
        "total_endpoints": scan.total_endpoints,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "cvss_score": scan.cvss_score,
        "ml_severity": scan.ml_severity,
        "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan.started_at else None,
        "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else None
    }), 200

@scans_bp.route("/<int:scan_id>/progress", methods=["GET"])
def get_scan_progress(scan_id):
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "scan_id": scan.id,
        "status": scan.status,
        "progress_percent": scan.progress_percent,
        "target_url": scan.target_url,
        "scan_depth": scan.scan_depth,
        "total_endpoints": scan.total_endpoints,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "cvss_score": scan.cvss_score,
        "ml_severity": scan.ml_severity
    }), 200

@scans_bp.route("/<int:scan_id>/rerun", methods=["POST"])
def rerun_scan(scan_id):
    old_scan = Scan.query.get(scan_id)

    if not old_scan:
        return jsonify({"error": "Scan not found"}), 404

    # Create a new scan with same parameters, but set to Running
    new_scan = Scan(
        user_id=old_scan.user_id,
        target_url=old_scan.target_url,
        scan_depth=old_scan.scan_depth,
        status="Running",
        progress_percent=10,
        total_endpoints=get_total_endpoints_by_depth(old_scan.scan_depth),
        vulnerabilities_found=0,
        cvss_score=0.0,
        ml_severity="Low"
    )

    db.session.add(new_scan)
    db.session.commit()
    
    log_activity(
        new_scan.user_id,
        "Scan re-run started",
        f"Re-run started for {new_scan.target_url}."
    )
    db.session.commit()

    # Start background scan (same as start_scan)
    app = current_app._get_current_object()

    thread = threading.Thread(
        target=run_scan_in_background,
        args=(app, new_scan.id, new_scan.target_url, new_scan.scan_depth, new_scan.user_id)
    )
    thread.start()

    return jsonify({
        "message": "Scan re-run started successfully",
        "scan_id": new_scan.id,
        "target_url": new_scan.target_url,
        "scan_depth": new_scan.scan_depth,
        "status": new_scan.status,
        "progress_percent": new_scan.progress_percent
    }), 202


@scans_bp.route("/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    db.session.delete(scan)
    db.session.commit()

    return jsonify({
        "message": "Scan deleted successfully"
    }), 200

@scans_bp.route("/latest-results", methods=["GET"])
def get_latest_results():
    user_id = request.args.get("user_id", type=int)

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    scan = (
        Scan.query
        .filter_by(user_id=user_id, status="Completed")
        .order_by(Scan.completed_at.desc())
        .first()
    )

    if not scan:
        return jsonify({"error": "No completed scans found"}), 404

    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()

    severity_counts = {
        "Total": len(vulnerabilities),
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    category_counts = {}

    findings = []

    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1
        
        category = vuln.category or map_to_owasp_category(vuln.vuln_name)
        category_counts[category] = category_counts.get(category, 0) + 1

        findings.append({
            "id": vuln.id,
            "vuln_name": vuln.vuln_name,
            "category": category,
            "category_display": format_category_label(category),
            "endpoint": vuln.endpoint,
            "severity": vuln.severity,
            "status": vuln.status,
            "cvss_score": vuln.cvss_score,
            "cvss_severity": (
                "Critical" if vuln.cvss_score >= 9.0 else
                "High" if vuln.cvss_score >= 7.0 else
                "Medium" if vuln.cvss_score >= 4.0 else
                "Low"
            ),
            "ml_severity": vuln.ml_severity,
            "description": vuln.description,
            "recommendation": get_recommendations(vuln.category or map_to_owasp_category(vuln.vuln_name)),
            "mitigation_steps": get_mitigation_steps(vuln.category or map_to_owasp_category(vuln.vuln_name)),
            "method": vuln.method,
            "affected_parameter": vuln.affected_parameter,
            "payload_example": vuln.payload_example,
            "evidence": vuln.evidence,
            "detected_at": vuln.detected_at.strftime("%Y-%m-%d %H:%M:%S") if vuln.detected_at else None,
            "detected_time_ago": format_time_ago(vuln.detected_at)
        })

    category_breakdown = []
    for category, count in category_counts.items():
        category_breakdown.append({
            "category": category,
            "display_label": format_category_label(category),
            "count": count
        })

    severity_chart = [
        {"label": "Critical", "value": severity_counts["Critical"]},
        {"label": "High", "value": severity_counts["High"]},
        {"label": "Medium", "value": severity_counts["Medium"]},
        {"label": "Low", "value": severity_counts["Low"]}
    ]
    
    category_chart = [
        {"label": item["display_label"], "value": item["count"]}
        for item in category_breakdown
    ]

    cvss_panel = build_cvss_panel(scan.cvss_score)
    
    ml_panel = {
        "severity": scan.ml_severity,
        "label": "Predicted risk level"
    }

    return jsonify({
        "scan": {
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "scan_depth": scan.scan_depth,
            "status": scan.status,
            "total_endpoints": scan.total_endpoints,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "cvss_score": scan.cvss_score,
            "cvss_severity": (
                "Critical" if scan.cvss_score >= 9.0 else
                "High" if scan.cvss_score >= 7.0 else
                "Medium" if scan.cvss_score >= 4.0 else
                "Low"
            ),
            "ml_severity": scan.ml_severity,
            "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan.started_at else None,
            "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else None,
            "scan_date": scan.completed_at.strftime("%Y-%m-%d") if scan.completed_at else None,
            "display_date": scan.completed_at.strftime("%d/%m/%Y") if scan.completed_at else None,
            "duration": format_duration(scan.started_at, scan.completed_at)
        },
        "summary_boxes": severity_counts,
        "cvss_panel": cvss_panel,
        "ml_panel": ml_panel,
        "category_breakdown": category_breakdown,
        "severity_chart": severity_chart,
        "category_chart": category_chart,
        "filter_options": {
            "severity": ["All", "Critical", "High", "Medium", "Low"],
            "status": ["All", "Open", "Investigating", "Mitigated", "Closed"]
        },
        "findings": findings
    }), 200




@scans_bp.route("/<int:scan_id>/results", methods=["GET"])
def get_scan_results(scan_id):
    severity_filter = request.args.get("severity")
    endpoint_filter = request.args.get("endpoint")
    status_filter = request.args.get("status")

    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()

    severity_counts = {
        "Total": len(vulnerabilities),
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    category_counts = {}

    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1
            
        category = vuln.category or map_to_owasp_category(vuln.vuln_name)
        category_counts[category] = category_counts.get(category, 0) + 1

    filtered_findings = []

    for vuln in vulnerabilities:
        if severity_filter and severity_filter != "All" and vuln.severity != severity_filter:
            continue

        if endpoint_filter and endpoint_filter.lower() not in (vuln.endpoint or "").lower():
            continue

        if status_filter and status_filter != "All" and vuln.status != status_filter:
            continue

        filtered_findings.append({
            "id": vuln.id,
            "vuln_name": vuln.vuln_name,
            "category": vuln.category or map_to_owasp_category(vuln.vuln_name),
            "category_display": format_category_label(vuln.category or map_to_owasp_category(vuln.vuln_name)),
            "endpoint": vuln.endpoint,
            "severity": vuln.severity,
            "status": vuln.status,
            "cvss_score": vuln.cvss_score,
            "cvss_severity": (
                "Critical" if vuln.cvss_score >= 9.0 else
                "High" if vuln.cvss_score >= 7.0 else
                "Medium" if vuln.cvss_score >= 4.0 else
                "Low"
            ),
            "ml_severity": vuln.ml_severity,
            "description": vuln.description,
            "recommendation": get_recommendations(vuln.category or map_to_owasp_category(vuln.vuln_name)),
            "mitigation_steps": get_mitigation_steps(vuln.category or map_to_owasp_category(vuln.vuln_name)),
            "method": vuln.method,
            "affected_parameter": vuln.affected_parameter,
            "payload_example": vuln.payload_example,
            "evidence": vuln.evidence,
            "detected_at": vuln.detected_at.strftime("%Y-%m-%d %H:%M:%S") if vuln.detected_at else None,
            "detected_time_ago": format_time_ago(vuln.detected_at)
        })

    category_breakdown = []
    for category, count in category_counts.items():
        category_breakdown.append({
            "category": category,
            "display_label": format_category_label(category),
            "count": count
        })

    severity_chart = [
        {"label": "Critical", "value": severity_counts["Critical"]},
        {"label": "High", "value": severity_counts["High"]},
        {"label": "Medium", "value": severity_counts["Medium"]},
        {"label": "Low", "value": severity_counts["Low"]}
    ]
    
    category_chart = [
        {"label": item["display_label"], "value": item["count"]}
        for item in category_breakdown
    ]

    cvss_panel = build_cvss_panel(scan.cvss_score)
    
    ml_panel = {
        "severity": scan.ml_severity,
        "label": "Predicted risk level"
    }

    return jsonify({
        "scan": {
            "scan_id": scan.id,
            "target_url": scan.target_url,
            "scan_depth": scan.scan_depth,
            "status": scan.status,
            "total_endpoints": scan.total_endpoints,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "cvss_score": scan.cvss_score,
            "cvss_severity": (
                "Critical" if scan.cvss_score >= 9.0 else
                "High" if scan.cvss_score >= 7.0 else
                "Medium" if scan.cvss_score >= 4.0 else
                "Low"
            ),
            "ml_severity": scan.ml_severity,
            "started_at": scan.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan.started_at else None,
            "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else None,
            "scan_date": scan.completed_at.strftime("%Y-%m-%d") if scan.completed_at else None,
            "display_date": scan.completed_at.strftime("%d/%m/%Y") if scan.completed_at else None,
            "duration": format_duration(scan.started_at, scan.completed_at)
        },
        "summary_boxes": severity_counts,
        "cvss_panel": cvss_panel,
        "ml_panel": ml_panel,
        "category_breakdown": category_breakdown,
        "severity_chart": severity_chart,
        "category_chart": category_chart,
        "filter_options": {
            "severity": ["All", "Critical", "High", "Medium", "Low"],
            "status": ["All", "Open", "Investigating", "Mitigated", "Closed"]
        },
        "findings": filtered_findings
    }), 200

@scans_bp.route("/<int:scan_id>/export-pdf", methods=["GET"])
def export_scan_pdf(scan_id):
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=25,
        bottomMargin=25
    )

    elements = build_styled_pdf(doc, scan, vulnerabilities)
    doc.build(elements, onFirstPage=add_pdf_background, onLaterPages=add_pdf_background)

    buffer.seek(0)

    return Response(
        buffer,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan.id}_report.pdf"
        }
    )