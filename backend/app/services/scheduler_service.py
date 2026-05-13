from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from app.extensions import db
from app.models import UserPreference, Scan, User
from app.routes.scans import run_scan_in_background

scheduler = BackgroundScheduler()


def run_auto_scans(app):
    with app.app_context():
        print("[AUTO SCAN CHECK RUNNING]")
        preferences = UserPreference.query.filter_by(auto_scan=True).all()

        for pref in preferences:
            user = User.query.get(pref.user_id)
            if not user:
                continue

            last_scan = (
                Scan.query.filter_by(user_id=user.id)
                .order_by(Scan.created_at.desc())
                .first()
            )

            if pref.summary_reports == "Weekly":
                if not last_scan or (datetime.utcnow() - last_scan.created_at) > timedelta(days=7):
                    start_auto_scan(app, user)

            elif pref.summary_reports == "Monthly":
                if not last_scan or (datetime.utcnow() - last_scan.created_at) > timedelta(days=30):
                    start_auto_scan(app, user)

            elif pref.summary_reports == "Daily":
                if not last_scan or (datetime.utcnow() - last_scan.created_at) > timedelta(days=1):
                    start_auto_scan(app, user)


def start_auto_scan(app, user):
    print(f"[AUTO SCAN TRIGGERED] user_id={user.id}")

    scan = Scan(
        user_id=user.id,
        target_url="https://auto-scan.example.com",
        scan_depth="standard",
        status="Running",
        progress_percent=5
    )

    db.session.add(scan)
    db.session.commit()

    run_scan_in_background(
        app,
        scan.id,
        scan.target_url,
        scan.scan_depth,
        user.id
    )


def delete_old_scans(app):
    with app.app_context():
        print("[DELETE OLD SCANS CHECK RUNNING]")
        preferences = UserPreference.query.filter_by(delete_old_scans=True).all()

        for pref in preferences:
            cutoff = datetime.utcnow() - timedelta(days=30)

            old_scans = Scan.query.filter(
                Scan.user_id == pref.user_id,
                Scan.created_at < cutoff
            ).all()

            for scan in old_scans:
                db.session.delete(scan)

            db.session.commit()

            if old_scans:
                print(f"[DELETED {len(old_scans)} OLD SCANS] user_id={pref.user_id}")


def start_scheduler(app):
    if not scheduler.running:
        scheduler.add_job(func=run_auto_scans, trigger="interval", minutes=1, args=[app])
        scheduler.add_job(func=delete_old_scans, trigger="interval", minutes=2, args=[app])

        scheduler.start()
        print("[SCHEDULER STARTED]")