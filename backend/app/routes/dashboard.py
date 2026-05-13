from flask import Blueprint, request, jsonify
from sqlalchemy import func
from datetime import datetime, timedelta

from app.extensions import db
from app.models import Scan, Vulnerability, Alert

dashboard_bp = Blueprint("dashboard", __name__)

def format_time_ago(dt):
    from datetime import datetime
    now = datetime.utcnow()
    diff = now - dt

    minutes = diff.seconds // 60
    hours = diff.seconds // 3600

    if minutes < 1:
        return "Just now"
    elif minutes < 60:
        return f"{minutes} min ago"
    elif hours < 24:
        return f"{hours} hr ago"
    else:
        return dt.strftime("%Y-%m-%d")


@dashboard_bp.route("/summary", methods=["GET"])
def get_dashboard_summary():
    user_id = request.args.get("user_id", type=int)
    period = request.args.get("period", "week")
    month_page = request.args.get("month_page", 0, type=int)

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    completed_scans = (
        Scan.query
        .filter_by(user_id=user_id, status="Completed")
        .order_by(Scan.completed_at.desc())
        .all()
    )

    latest_scan = completed_scans[0] if completed_scans else None

    # Total APIs scanned so far = sum of total_endpoints across completed scans
    total_apis_scanned = sum(scan.total_endpoints or 0 for scan in completed_scans)

    # Total vulnerabilities found so far
    total_vulnerabilities = sum(scan.vulnerabilities_found or 0 for scan in completed_scans)

    # Severity breakdown from all vulnerabilities belonging to this user
    vulnerabilities = (
        db.session.query(Vulnerability)
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .filter(Scan.user_id == user_id)
        .order_by(Vulnerability.detected_at.desc())
        .all()
    )

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1

    severity_chart = [
        {"label": "Critical", "value": severity_counts["Critical"]},
        {"label": "High", "value": severity_counts["High"]},
        {"label": "Medium", "value": severity_counts["Medium"]},
        {"label": "Low", "value": severity_counts["Low"]}
    ]

    # Recent threats detected table
    recent_threats = []
    for vuln in vulnerabilities[:10]:
        recent_threats.append({
            "id": vuln.id,
            "endpoint": vuln.endpoint,
            "type": vuln.category,
            "severity": vuln.severity,
            "ml_severity": vuln.ml_severity,
            "cvss_score": vuln.cvss_score,
            "status": vuln.status,
            "time": format_time_ago(vuln.detected_at)
        })

    # Active alerts count
    active_alerts = Alert.query.filter_by(user_id=user_id, status="Open").count()

    # Last scan summary
    last_scan_summary = None
    if latest_scan:
        last_scan_summary = {
            "scan_id": latest_scan.id,
            "endpoints": latest_scan.total_endpoints,
            "vulnerabilities": latest_scan.vulnerabilities_found,
            "cvss_score": latest_scan.cvss_score,
            "ml_severity": latest_scan.ml_severity,
            "target_url": latest_scan.target_url,
            "completed_at": latest_scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if latest_scan.completed_at else None
        }

    # Threat activity chart
    threat_activity = []

    if period == "month":
        today = datetime.utcnow()
        year = today.year
        
        if month_page == 0:
            month_numbers = [1, 2, 3, 4, 5, 6]
        else:
            month_numbers = [7, 8, 9, 10, 11, 12]
            
        for month_num in month_numbers:
            month_start = datetime(year, month_num, 1)
            
            if month_num == 12:
                next_month = datetime(year + 1, 1, 1)
            else:
                next_month = datetime(year, month_num + 1, 1)
            
            vuln_count = (
                db.session.query(Vulnerability)
                .join(Scan, Vulnerability.scan_id == Scan.id)
                .filter(
                    Scan.user_id == user_id,
                    Vulnerability.detected_at >= month_start,
                    Vulnerability.detected_at < next_month
                )
                .count()
            )
            
            threat_activity.append({
                "label": month_start.strftime("%b"),
                "value": vuln_count
            })

    else:
        # Last 7 days
        today = datetime.utcnow()
        for i in range(6, -1, -1):
            day = today - timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)

            vuln_count = (
                db.session.query(Vulnerability)
                .join(Scan, Vulnerability.scan_id == Scan.id)
                .filter(
                    Scan.user_id == user_id,
                    Vulnerability.detected_at >= day_start,
                    Vulnerability.detected_at < day_end
                )
                .count()
            )

            threat_activity.append({
                "label": day.strftime("%a"),
                "value": vuln_count
            })

    # Category chart (optional but useful later)
    category_rows = (
        db.session.query(Vulnerability.category, func.count(Vulnerability.id))
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .filter(Scan.user_id == user_id)
        .group_by(Vulnerability.category)
        .all()
    )

    category_chart = [
        {"label": row[0], "value": row[1]}
        for row in category_rows if row[0]
    ]

    return jsonify({
        "top_cards": {
            "total_apis": total_apis_scanned,
            "vulnerabilities": total_vulnerabilities,
            "critical_count": severity_counts["Critical"],
            "high_count": severity_counts["High"],
            "cvss_score": latest_scan.cvss_score if latest_scan else 0.0,
            "ml_severity": latest_scan.ml_severity if latest_scan else "Low",
            "active_alerts": active_alerts
        },
        "last_scan_summary": last_scan_summary,
        "recent_threats": recent_threats,
        "severity_breakdown": severity_counts,
        "severity_chart": severity_chart,
        "threat_activity": threat_activity,
        "category_chart": category_chart
    }), 200