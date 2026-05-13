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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
import threading
from flask import current_app



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


def generate_scan_pdf_file(scan, vulnerabilities):
    reports_dir = os.path.join(os.getcwd(), "generated_reports")
    os.makedirs(reports_dir, exist_ok=True)

    file_path = os.path.join(reports_dir, f"scan_{scan.id}_report.pdf")

    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("SentinelGate Scan Report", styles["Title"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(f"Target URL: {scan.target_url}", styles["Normal"]))
    elements.append(Paragraph(f"Scan Depth: {scan.scan_depth}", styles["Normal"]))
    elements.append(Paragraph(f"CVSS Score: {scan.cvss_score}", styles["Normal"]))
    elements.append(Paragraph(f"ML Severity: {scan.ml_severity}", styles["Normal"]))
    elements.append(Paragraph(f"Duration: {format_duration(scan.started_at, scan.completed_at)}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1

    elements.append(Paragraph("Summary", styles["Heading2"]))
    for key, value in severity_counts.items():
        elements.append(Paragraph(f"{key}: {value}", styles["Normal"]))

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Detailed Findings", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for vuln in vulnerabilities:
        elements.append(Paragraph(f"Name: {vuln.vuln_name}", styles["Normal"]))
        elements.append(Paragraph(f"Endpoint: {vuln.endpoint}", styles["Normal"]))
        elements.append(Paragraph(f"Final Risk Severity: {vuln.severity}", styles["Normal"]))
        elements.append(Paragraph(f"CVSS Score: {vuln.cvss_score}", styles["Normal"]))
        elements.append(Paragraph(f"ML Prediction Severity: {vuln.ml_severity}", styles["Normal"]))
        elements.append(Paragraph(f"Category: {format_category_label(vuln.category)}", styles["Normal"]))
        elements.append(Paragraph(f"Description: {vuln.description}", styles["Normal"]))
        elements.append(Paragraph(f"Evidence: {vuln.evidence}", styles["Normal"]))
        elements.append(Paragraph(f"Recommendation: {vuln.recommendation}", styles["Normal"]))
        elements.append(Spacer(1, 10))

    doc.build(elements)
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

    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("SentinelGate Scan Report", styles["Title"]))
    elements.append(Spacer(1, 10))

    # Scan info
    elements.append(Paragraph(f"Target URL: {scan.target_url}", styles["Normal"]))
    elements.append(Paragraph(f"Scan Depth: {scan.scan_depth}", styles["Normal"]))
    elements.append(Paragraph(f"CVSS Score: {scan.cvss_score}", styles["Normal"]))
    elements.append(Paragraph(f"ML Severity: {scan.ml_severity}", styles["Normal"]))
    elements.append(Paragraph(f"Duration: {format_duration(scan.started_at, scan.completed_at)}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    # Summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1

    elements.append(Paragraph("Summary", styles["Heading2"]))
    for key, value in severity_counts.items():
        elements.append(Paragraph(f"{key}: {value}", styles["Normal"]))

    elements.append(Spacer(1, 15))

    # Findings
    elements.append(Paragraph("Detailed Findings", styles["Heading2"]))
    elements.append(Spacer(1, 10))

    for vuln in vulnerabilities:
        elements.append(Paragraph(f"Name: {vuln.vuln_name}", styles["Normal"]))
        elements.append(Paragraph(f"Endpoint: {vuln.endpoint}", styles["Normal"]))
        elements.append(Paragraph(f"Final Risk Severity: {vuln.severity}", styles["Normal"]))
        elements.append(Paragraph(f"CVSS Score: {vuln.cvss_score}", styles["Normal"]))
        elements.append(Paragraph(f"ML Prediction Severity: {vuln.ml_severity}", styles["Normal"]))
        elements.append(Paragraph(f"Category: {format_category_label(vuln.category)}", styles["Normal"]))
        elements.append(Paragraph(f"Description: {vuln.description}", styles["Normal"]))
        elements.append(Paragraph(f"Evidence: {vuln.evidence}", styles["Normal"]))
        elements.append(Paragraph(f"Recommendation: {vuln.recommendation}", styles["Normal"]))
        elements.append(Spacer(1, 10))

    doc.build(elements)

    buffer.seek(0)

    return Response(
        buffer,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan.id}_report.pdf"
        }
    )