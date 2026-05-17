# ---------------------------------------------------------
# This file manages authentication and account security for
# SentinelGate. It handles registration, login, and Microsoft
# Authenticator MFA, password recovery, sessions, logout,
# and account deletion.
# ---------------------------------------------------------

from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import pyotp
import qrcode
import base64
from io import BytesIO
import secrets
from app.services.email_service import send_email_notification
from app.extensions import db
from app.models import User, OTPCode, ActivityLog, UserSession
import re

auth_bp = Blueprint("auth", __name__)

APP_ISSUER = "SentinelGate"

# Check whether a password meets the required security rules
def is_strong_password(password):
    return bool(re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[^\w\s]).{8,}$", password))
    
# Identify the user's browser and device from the request header
def get_device_name():
    ua = request.headers.get("User-Agent", "").lower()

    # Browser
    if "edg/" in ua:
        browser = "Edge"
    elif "chrome/" in ua and "safari/" in ua:
        browser = "Chrome"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    # Device type + OS
    if "iphone" in ua:
        device = "iPhone Mobile"
    elif "ipad" in ua:
        device = "iPad Tablet"
    elif "android" in ua:
        if "mobile" in ua:
            device = "Android Phone"
        else:
            device = "Android Tablet"
    elif "macintosh" in ua or "mac os" in ua:
        device = "Apple Laptop"
    elif "windows" in ua:
        device = "Windows Laptop"
    else:
        device = "Unknown Device"

    return f"{browser} on {device}"

# Create or update a login session for the current user device
def create_user_session(user):
    device_name = get_device_name()
    ip_address = request.remote_addr
    UserSession.query.filter_by(
        user_id=user.id,
        is_active=True
    ).update({"is_current": False})

    existing_session = UserSession.query.filter_by(
        user_id=user.id,
        device_name=device_name,
        ip_address=ip_address,
        is_active=True
    ).first()

    if existing_session:
        existing_session.last_active_at = datetime.utcnow()
        existing_session.is_current = True
        return existing_session

    session = UserSession(
        session_token=secrets.token_urlsafe(32),
        device_name=device_name,
        ip_address=ip_address,
        is_current=True,
        is_active=True,
        last_active_at=datetime.utcnow(),
        user_id=user.id
    )

    db.session.add(session)
    return session

# Store an activity log entry for important user actions
def log_activity(user_id, action, description):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        description=description
    )
    db.session.add(log)

# Test route used to confirm that the authentication blueprint is working    
@auth_bp.route("/test")
def test_auth():
    return {"message": "auth route working"}

# Register a new user and store their password securely
@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    full_name = data.get("full_name")
    email = data.get("email")
    company_name = data.get("company_name")
    password = data.get("password")

    if not full_name or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    if not is_strong_password(password):
        return jsonify({
            "error": "Password must be at least 8 characters and include letters, numbers, and a symbol."
        }), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password)

    new_user = User(
        full_name=full_name,
        email=email,
        company_name=company_name,
        password_hash=hashed_password,
        mfa_enabled=True,
        mfa_configured=False
    )

    db.session.add(new_user)
    db.session.commit()

    log_activity(new_user.id, "Account created", "User account was registered successfully.")
    db.session.commit()

    return jsonify({
        "message": "User registered successfully",
        "user_id": new_user.id
    }), 201

# Generate the Microsoft Authenticator secret and QR code for MFA setup
@auth_bp.route("/setup-mfa", methods=["POST"])
def setup_mfa():
    data = request.get_json()
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()

    totp = pyotp.TOTP(user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name=APP_ISSUER
    )

    # Generate QR code image
    qr = qrcode.make(provisioning_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)

    qr_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

    db.session.commit()

    return jsonify({
        "message": "MFA setup data generated successfully",
        "user_id": user.id,
        "email": user.email,
        "manual_secret": user.mfa_secret,
        "provisioning_uri": provisioning_uri,
        "qr_code_base64": qr_base64
    }), 200

# Confirm the first MFA code and complete the MFA setup process
@auth_bp.route("/confirm-mfa", methods=["POST"])
def confirm_mfa():
    data = request.get_json()

    user_id = data.get("user_id")
    code = data.get("code")

    if not user_id or not code:
        return jsonify({"error": "User ID and code are required"}), 400

    user = User.query.get(user_id)
    if not user or not user.mfa_secret:
        return jsonify({"error": "MFA setup has not been started"}), 400

    totp = pyotp.TOTP(user.mfa_secret)

    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid authenticator code"}), 400

    user.mfa_configured = True
    user.mfa_enabled = True
    user.last_login = datetime.utcnow()
    session = create_user_session(user)
    log_activity(user.id, "MFA configured", "Microsoft Authenticator MFA was configured successfully.")
    log_activity(user.id, "Login successful", "User logged in successfully after initial MFA setup.")
    db.session.commit()
    
    return jsonify({
        "message": "Microsoft Authenticator MFA configured successfully",
        "session_token": session.session_token,
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "company_name": user.company_name
        }
    }), 200

# Validate email and password, then decide whether MFA setup or MFA verification is needed
@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    # MFA not configured yet -> send user to setup page
    if not user.mfa_configured:
        return jsonify({
            "message": "MFA setup required",
            "user_id": user.id,
            "email": user.email,
            "setup_required": True
        }), 200

    # MFA configured -> ask for authenticator code
    if user.mfa_enabled and user.mfa_configured:
        return jsonify({
            "message": "Enter the code from Microsoft Authenticator",
            "user_id": user.id,
            "email": user.email,
            "mfa_required": True
        }), 200

    # fallback direct login
    user.last_login = datetime.utcnow()
    session = create_user_session(user)
    log_activity(user.id, "Login successful", "User logged in successfully.")
    db.session.commit()

    return jsonify({
        "message": "Login successful",
        "session_token": session.session_token,
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "company_name": user.company_name
        }
    }), 200

# Verify the Microsoft Authenticator code during login
@auth_bp.route("/verify-mfa", methods=["POST"])
def verify_mfa():
    data = request.get_json()

    user_id = data.get("user_id")
    code = data.get("code")

    if not user_id or not code:
        return jsonify({"error": "User ID and code are required"}), 400

    user = User.query.get(user_id)

    if not user or not user.mfa_secret:
        return jsonify({"error": "MFA is not configured for this user"}), 400

    totp = pyotp.TOTP(user.mfa_secret)

    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid or expired authenticator code"}), 400

    user.last_login = datetime.utcnow()
    session = create_user_session(user)
    log_activity(user.id, "Login successful", "User logged in successfully after MFA verification.")
    db.session.commit()

    return jsonify({
        "message": "MFA verified successfully",
        "session_token": session.session_token,
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "company_name": user.company_name
        }
    }), 200

# Generate and email a password reset OTP to the user
@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()

    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    old_tokens = OTPCode.query.filter_by(
        user_id=user.id,
        purpose="password_reset_link",
        is_used=False
    ).all()

    for token in old_tokens:
        db.session.delete(token)

    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=15)

    new_token = OTPCode(
        code=reset_token,
        purpose="password_reset_link",
        expires_at=expires_at,
        user_id=user.id
    )

    db.session.add(new_token)
    db.session.commit()

    reset_link = f"http://localhost:3000/reset-password?token={reset_token}"

    send_email_notification(
        user.email,
        "SentinelGate Password Reset",
        (
            f"You requested a password reset.\n\n"
            f"Click the link below to reset your password:\n"
            f"{reset_link}\n\n"
            f"This link will expire in 15 minutes.\n"
            f"If you did not request this, you can ignore this email."
        )
    )

    return jsonify({
        "message": "Password reset link sent successfully",
        "email": user.email
    }), 200

# Verify the reset OTP and update the user's password
@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()

    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        return jsonify({"error": "token and new_password are required"}), 400
    
    if not is_strong_password(new_password):
        return jsonify({
            "error": "Password must be at least 8 characters and include letters, numbers, and a symbol."
        }), 400

    reset_record = OTPCode.query.filter_by(
        code=token,
        purpose="password_reset_link",
        is_used=False
    ).first()

    if not reset_record:
        return jsonify({"error": "Invalid reset link"}), 400

    if reset_record.expires_at < datetime.utcnow():
        return jsonify({"error": "Reset link has expired"}), 400

    user = User.query.get(reset_record.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password_hash = generate_password_hash(new_password)
    reset_record.is_used = True

    log_activity(user.id, "Password reset", "User reset password successfully.")
    db.session.commit()

    return jsonify({
        "message": "Password reset successfully"
    }), 200

# Log out the current user session
@auth_bp.route("/logout", methods=["POST"])
def logout():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    session_token = data.get("session_token")

    if user_id and session_token:
        current_session = UserSession.query.filter_by(
            user_id=user_id,
            session_token=session_token,
            is_active=True
        ).first()

        if current_session:
            current_session.is_active = False
            current_session.is_current = False

        log_activity(user_id, "Logout", "User logged out successfully.")
        db.session.commit()

    return jsonify({
        "message": "Logout successful",
        "redirect_to": "/"
    }), 200
