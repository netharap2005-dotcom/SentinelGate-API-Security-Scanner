from datetime import datetime
from app.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    company_name = db.Column(db.String(150), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)

    mfa_enabled = db.Column(db.Boolean, default=True)
    mfa_secret = db.Column(db.String(255), nullable=True)
    mfa_configured = db.Column(db.Boolean, default=False)

    api_key = db.Column(db.String(255), nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("Scan", backref="user", lazy=True, cascade="all, delete-orphan")
    otp_codes = db.relationship("OTPCode", backref="user", lazy=True, cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="user", lazy=True, cascade="all, delete-orphan")
    preferences = db.relationship("UserPreference", backref="user", uselist=False, cascade="all, delete-orphan")
    activity_logs = db.relationship("ActivityLog", backref="user", lazy=True, cascade="all, delete-orphan")

class OTPCode(db.Model):
    __tablename__ = "otp_codes"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(50), nullable=False)  # login_mfa, password_reset, delete_account
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_depth = db.Column(db.String(50), nullable=False)  # shallow, standard, deep
    status = db.Column(db.String(50), default="Running")   # running, completed, failed
    progress_percent = db.Column(db.Integer, default=0)
    total_endpoints = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    cvss_score = db.Column(db.Float, nullable=True)
    ml_severity = db.Column(db.String(50), nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    vulnerabilities = db.relationship("Vulnerability", backref="scan", lazy=True, cascade="all, delete-orphan")


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    vuln_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    severity = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default="Open")  # open, investigating, mitigated, closed
    cvss_score = db.Column(db.Float, nullable=True)
    ml_severity = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)
    method = db.Column(db.String(20), nullable=True)
    affected_parameter = db.Column(db.String(100), nullable=True)
    payload_example = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    evidence = db.Column(db.Text, nullable=True)

    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(50), nullable=False)   # Critical, High, Medium, Low
    status = db.Column(db.String(50), default="Open")     # Open, Investigating, Resolved
    message = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)

    endpoint = db.Column(db.String(255), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    ml_severity = db.Column(db.String(50), nullable=True)

    email_sent = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


class UserPreference(db.Model):
    __tablename__ = "user_preferences"

    id = db.Column(db.Integer, primary_key=True)
    auto_scan = db.Column(db.Boolean, default=False)
    summary_reports = db.Column(db.String(50), default="Weekly")
    auto_download_report = db.Column(db.Boolean, default=False)
    delete_old_scans = db.Column(db.Boolean, default=False)
    alert_threshold = db.Column(db.String(100), nullable=True)

    email_alerts = db.Column(db.Boolean, default=True)
    email_scan_complete = db.Column(db.Boolean, default=True)
    real_time_notifications = db.Column(db.Boolean, default=False)
    critical_vulnerability_alerts = db.Column(db.Boolean, default=True)

    export_format = db.Column(db.String(20), default="PDF")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

class UserSession(db.Model):
    __tablename__ = "user_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    device_name = db.Column(db.String(150), nullable=False, default="Unknown Device")
    ip_address = db.Column(db.String(100), nullable=True)
    is_current = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    user = db.relationship("User", backref=db.backref("sessions", lazy=True, cascade="all, delete-orphan"))    