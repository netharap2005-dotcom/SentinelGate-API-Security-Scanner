from datetime import datetime
from datetime import timedelta

from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from app.extensions import db
from app.models import User, UserPreference, ActivityLog, Scan, Alert, UserSession
import secrets

settings_bp = Blueprint("settings", __name__)


def log_activity(user_id, action, description):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        description=description
    )
    db.session.add(log)


def get_or_create_preference(user_id):
    user = User.query.get(user_id)
    if not user:
        return None

    preference = UserPreference.query.filter_by(user_id=user_id).first()

    if not preference:
        preference = UserPreference(
            user_id=user_id,
            alert_threshold="cvss>7_or_ml_high_critical",
            email_alerts=True,
            email_scan_complete=True,
            real_time_notifications=False,
            critical_vulnerability_alerts=True,
            summary_reports="Weekly",
            export_format="PDF"
        )
        db.session.add(preference)
        db.session.commit()

    return preference


@settings_bp.route("/test")
def test_settings():
    return {"message": "settings route working"}


@settings_bp.route("", methods=["GET"])
def get_settings():
    user_id = request.args.get("user_id", type=int)

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    preference = get_or_create_preference(user_id)
    if not preference:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "account_details": {
            "user_id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "company_name": user.company_name,
        },
        "security_session": {
            "mfa_enabled": user.mfa_enabled,
            "mfa_configured": user.mfa_configured,
            "last_login": (user.last_login + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S") if user.last_login else None,
            "active_sessions": UserSession.query.filter_by(user_id=user.id, is_active=True).count()
        },
        "scan_automation": {
            "auto_scan": preference.auto_scan,
            "summary_reports": preference.summary_reports,
            "auto_download_report": preference.auto_download_report,
            "delete_old_scans": preference.delete_old_scans,
            "alert_threshold": preference.alert_threshold
        },
        "notifications": {
            "email_alerts": preference.email_alerts,
            "email_scan_complete": preference.email_scan_complete,
            "real_time_notifications": preference.real_time_notifications,
            "critical_vulnerability_alerts": preference.critical_vulnerability_alerts
        },
        "data_management": {
            "export_format": preference.export_format
        },
        "api_integration": {
            "api_key": user.api_key
        }
    }), 200


@settings_bp.route("/account", methods=["PUT"])
def update_account_details():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    old_name = user.full_name
    old_company = user.company_name
    old_email = user.email
    
    new_email = data.get("email", user.email)
    existing_user = User.query.filter(User.email == new_email, User.id != user.id).first()
    if existing_user:
        return jsonify({"error": "Email already in use"}), 400
    user.full_name = data.get("full_name", user.full_name)
    user.company_name = data.get("company_name", user.company_name)
    user.email = new_email

    db.session.commit()

    log_activity(
        user.id,
        "Account updated",
        f"Account details updated from name='{old_name}', company='{old_company}', email='{old_email}' to name='{user.full_name}', company='{user.company_name}', email='{user.email}'."
    )
    db.session.commit()

    return jsonify({
        "message": "Account details updated successfully"
    }), 200


@settings_bp.route("/password", methods=["PUT"])
def update_password():
    data = request.get_json()

    user_id = data.get("user_id")
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not user_id or not current_password or not new_password:
        return jsonify({"error": "user_id, current_password, and new_password are required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user.password_hash, current_password):
        return jsonify({"error": "Current password is incorrect"}), 400

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()

    log_activity(user.id, "Password updated", "Your account password was changed.")
    db.session.commit()

    return jsonify({
        "message": "Password updated successfully"
    }), 200


@settings_bp.route("/mfa", methods=["PUT"])
def update_mfa_setting():
    data = request.get_json()

    user_id = data.get("user_id")
    mfa_enabled = data.get("mfa_enabled")

    if user_id is None or mfa_enabled is None:
        return jsonify({"error": "user_id and mfa_enabled are required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.mfa_enabled = bool(mfa_enabled)
    db.session.commit()

    action_text = "enabled" if user.mfa_enabled else "disabled"
    log_activity(user.id, "MFA updated", f"Multi-factor authentication was {action_text}.")
    db.session.commit()

    return jsonify({
        "message": f"MFA {action_text} successfully"
    }), 200


@settings_bp.route("/preferences", methods=["PUT"])
def update_preferences():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    preference = get_or_create_preference(user_id)

    preference.auto_scan = data.get("auto_scan", preference.auto_scan)
    preference.summary_reports = data.get("summary_reports", preference.summary_reports)
    preference.auto_download_report = data.get("auto_download_report", preference.auto_download_report)
    preference.delete_old_scans = data.get("delete_old_scans", preference.delete_old_scans)
    preference.alert_threshold = data.get("alert_threshold", preference.alert_threshold)
    preference.email_alerts = data.get("email_alerts", preference.email_alerts)
    preference.email_scan_complete = data.get("email_scan_complete", preference.email_scan_complete)
    preference.real_time_notifications = data.get("real_time_notifications", preference.real_time_notifications)
    preference.critical_vulnerability_alerts = data.get("critical_vulnerability_alerts", preference.critical_vulnerability_alerts)
    preference.export_format = data.get("export_format", preference.export_format)

    db.session.commit()

    log_activity(user_id, "Settings updated", "Scan, notification, or export preferences were updated.")
    db.session.commit()

    return jsonify({
        "message": "Settings updated successfully"
    }), 200

@settings_bp.route("/manage-sessions", methods=["GET"])
def manage_sessions():
    user_id = request.args.get("user_id", type=int)
    session_token = request.args.get("session_token")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    active_sessions = UserSession.query.filter_by(
        user_id=user.id,
        is_active=True
    ).order_by(UserSession.last_active_at.desc()).all()

    current_session = None
    if session_token:
        current_session = UserSession.query.filter_by(
            user_id=user.id,
            session_token=session_token,
            is_active=True
        ).first()

    other_sessions = [
        s for s in active_sessions
        if not current_session or s.id != current_session.id
    ]

    return jsonify({
        "last_login": (user.last_login + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S") if user.last_login else None,
        "active_sessions_count": len(active_sessions),
        "current_session": {
            "id": current_session.id if current_session else None,
            "device_name": current_session.device_name if current_session else "This Device",
            "ip_address": current_session.ip_address if current_session else None,
            "last_active_at": (current_session.last_active_at + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S") if current_session and current_session.last_active_at else None,
            "status": "Active" if current_session else "Inactive"
        },
        "other_sessions": [
            {
                "id": session.id,
                "device_name": session.device_name,
                "ip_address": session.ip_address,
                "last_active_at": (session.last_active_at + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S") if session.last_active_at else None,
                "status": "Active"
            }
            for session in other_sessions
        ]
    }), 200

@settings_bp.route("/logout-all-sessions", methods=["POST"])
def logout_all_sessions():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    other_sessions = UserSession.query.filter(
        UserSession.user_id == user.id,
        UserSession.is_active == True,
        UserSession.is_current == False
    ).all()

    for session in other_sessions:
        session.is_active = False
        session.last_active_at = datetime.utcnow()

    log_activity(user.id, "Logout all sessions", "User logged out all other active sessions.")
    db.session.commit()

    return jsonify({
        "message": "All other sessions logged out successfully"
    }), 200

@settings_bp.route("/logout-session/<int:session_id>", methods=["POST"])
def logout_single_session(session_id):
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    session = UserSession.query.filter_by(
        id=session_id,
        user_id=user.id,
        is_active=True
    ).first()

    if not session:
        return jsonify({"error": "Session not found"}), 404

    if session.is_current:
        return jsonify({"error": "Current session should use normal logout"}), 400

    session.is_active = False
    session.last_active_at = datetime.utcnow()

    log_activity(user.id, "Session logged out", f"User logged out session {session_id}.")
    db.session.commit()

    return jsonify({
        "message": "Session logged out successfully"
    }), 200

@settings_bp.route("/activity-logs", methods=["GET"])
def get_activity_logs():
    user_id = request.args.get("user_id", type=int)

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    logs = ActivityLog.query.filter_by(user_id=user_id).order_by(ActivityLog.created_at.desc()).all()

    results = []
    for log in logs:
        results.append({
            "id": log.id,
            "action": log.action,
            "description": log.description,
            "created_at": log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else None
        })

    return jsonify({
        "count": len(results),
        "logs": results
    }), 200


@settings_bp.route("/api-key/regenerate", methods=["POST"])
def regenerate_api_key():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.api_key = "sk-sg_" + secrets.token_hex(16)
    db.session.commit()

    log_activity(user.id, "API key regenerated", "A new API key was generated.")
    db.session.commit()

    return jsonify({
        "message": "API key regenerated successfully",
        "api_key": user.api_key
    }), 200

@settings_bp.route("/clear-scan-history/start", methods=["POST"])
def start_clear_scan_history():
    data = request.get_json()

    user_id = data.get("user_id")
    password = data.get("password")
    mfa_code = data.get("mfa_code")

    if not user_id or not password or not mfa_code:
        return jsonify({"error": "user_id, password, and mfa_code are required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Password is incorrect"}), 400

    if not user.mfa_enabled or not user.mfa_secret:
        return jsonify({"error": "MFA is not enabled for this user"}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(mfa_code, valid_window=1):
        return jsonify({"error": "Invalid authenticator code"}), 400

    return jsonify({
        "message": "Scan history clear verification successful"
    }), 200

@settings_bp.route("/clear-scan-history/confirm", methods=["DELETE"])
def clear_scan_history():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    scans = Scan.query.filter_by(user_id=user_id).all()

    for scan in scans:
        db.session.delete(scan)

    db.session.commit()

    log_activity(user_id, "Scan history cleared", "All saved scan history was deleted after password and MFA verification.")
    db.session.commit()

    return jsonify({
        "message": "Scan history cleared successfully"
    }), 200

@settings_bp.route("/delete-account/start", methods=["POST"])
def start_delete_account():
    data = request.get_json()

    user_id = data.get("user_id")
    password = data.get("password")
    mfa_code = data.get("mfa_code")

    if not user_id or not password or not mfa_code:
        return jsonify({"error": "user_id, password, and mfa_code are required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Password is incorrect"}), 400

    if not user.mfa_enabled or not user.mfa_secret:
        return jsonify({"error": "MFA is not enabled for this user"}), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(mfa_code, valid_window=1):
        return jsonify({"error": "Invalid authenticator code"}), 400

    return jsonify({
        "message": "Delete account verification successful"
    }), 200

@settings_bp.route("/delete-account/confirm", methods=["DELETE"])
def delete_account():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({
        "message": "Account deleted successfully",
        "redirect_to": "/register"
    }), 200