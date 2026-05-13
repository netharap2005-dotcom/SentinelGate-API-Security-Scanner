from flask import Blueprint, request, jsonify
from datetime import datetime
from app.extensions import db
from app.models import Alert

alerts_bp = Blueprint("alerts", __name__)


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


@alerts_bp.route("/test")
def test_alerts():
    return {"message": "alerts route working"}


@alerts_bp.route("", methods=["GET"])
def get_alerts():
    user_id = request.args.get("user_id", type=int)

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    alerts = (
        Alert.query
        .filter_by(user_id=user_id)
        .order_by(Alert.created_at.desc())
        .all()
    )

    results = []
    for alert in alerts:
        results.append({
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "message": alert.message,
            "description": alert.message,
            "recommendation": alert.recommendation,
            "endpoint": alert.endpoint,
            "category": alert.category,
            "cvss_score": alert.cvss_score,
            "cvss": alert.cvss_score,
            "ml_severity": alert.ml_severity,
            "mlSeverity": alert.ml_severity,
            "email_sent": alert.email_sent,
            "emailSent": alert.email_sent,
            "is_read": alert.is_read,
            "unread": not alert.is_read,
            "created_at": alert.created_at.strftime("%Y-%m-%d %H:%M:%S") if alert.created_at else None,
            "time_ago": format_time_ago(alert.created_at),
            "timeLabel": format_time_ago(alert.created_at),
            "timeValue": int((datetime.utcnow() - alert.created_at).total_seconds() // 60) if alert.created_at else 999999,
            "resolved_at": alert.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if alert.resolved_at else None
        })

    return jsonify({"alerts": results}), 200


@alerts_bp.route("/<int:alert_id>", methods=["GET"])
def get_single_alert(alert_id):
    alert = Alert.query.get(alert_id)

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    return jsonify({
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "message": alert.message,
        "recommendation": alert.recommendation,
        "endpoint": alert.endpoint,
        "category": alert.category,
        "cvss_score": alert.cvss_score,
        "ml_severity": alert.ml_severity,
        "email_sent": alert.email_sent,
        "is_read": alert.is_read,
        "created_at": alert.created_at.strftime("%Y-%m-%d %H:%M:%S") if alert.created_at else None,
        "time_ago": format_time_ago(alert.created_at),
        "resolved_at": alert.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if alert.resolved_at else None
    }), 200


@alerts_bp.route("/mark-all-read", methods=["POST"])
def mark_all_read():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    alerts = Alert.query.filter_by(user_id=user_id, is_read=False).all()

    for alert in alerts:
        alert.is_read = True

    db.session.commit()

    return jsonify({
        "message": "All alerts marked as read"
    }), 200


@alerts_bp.route("/<int:alert_id>/investigate", methods=["POST"])
def set_investigate(alert_id):
    alert = Alert.query.get(alert_id)

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.status = "Investigating"
    alert.is_read = True
    db.session.commit()

    return jsonify({
        "message": "Alert moved to investigating"
    }), 200


@alerts_bp.route("/<int:alert_id>/resolve", methods=["POST"])
def set_resolve(alert_id):
    alert = Alert.query.get(alert_id)

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.status = "Resolved"
    alert.is_read = True
    alert.resolved_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        "message": "Alert resolved successfully"
    }), 200


@alerts_bp.route("/<int:alert_id>/read", methods=["POST"])
def mark_read(alert_id):
    alert = Alert.query.get(alert_id)

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    alert.is_read = True
    db.session.commit()

    return jsonify({
        "message": "Alert marked as read"
    }), 200


@alerts_bp.route("/<int:alert_id>", methods=["DELETE"])
def delete_alert(alert_id):
    alert = Alert.query.get(alert_id)

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    db.session.delete(alert)
    db.session.commit()

    return jsonify({
        "message": "Alert deleted successfully"
    }), 200