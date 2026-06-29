from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app import db
from app.models.expense import ExpenseReport, ExpenseStatus
from app.models.user import User
from app.services.email_service import (
    send_approval_notification,
    send_rejection_notification,
    send_payment_notification,
)
from datetime import datetime
from functools import wraps

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/")
@login_required
@admin_required
def dashboard():
    pending = ExpenseReport.query.filter(
        ExpenseReport.status.in_([ExpenseStatus.SUBMITTED, ExpenseStatus.UNDER_REVIEW])
    ).order_by(ExpenseReport.submitted_at).all()
    return render_template("admin/dashboard.html", pending=pending)


@admin_bp.route("/reports")
@login_required
@admin_required
def all_reports():
    status_filter = request.args.get("status")
    user_filter = request.args.get("user_id", type=int)
    query = ExpenseReport.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    if user_filter:
        query = query.filter_by(user_id=user_filter)
    reports = query.order_by(ExpenseReport.updated_at.desc()).all()
    users = User.query.filter_by(is_active=True).order_by(User.name).all()
    return render_template("admin/reports.html", reports=reports, users=users,
                           statuses=ExpenseStatus, status_filter=status_filter, user_filter=user_filter)


@admin_bp.route("/report/<int:report_id>")
@login_required
@admin_required
def view_report(report_id):
    report = ExpenseReport.query.get_or_404(report_id)
    if report.status == ExpenseStatus.SUBMITTED:
        report.status = ExpenseStatus.UNDER_REVIEW
        db.session.commit()
    return render_template("admin/review.html", report=report)


@admin_bp.route("/report/<int:report_id>/approve", methods=["POST"])
@login_required
@admin_required
def approve_report(report_id):
    report = ExpenseReport.query.get_or_404(report_id)
    approved_amount = request.form.get("approved_amount", "").replace(",", ".")
    try:
        report.approved_amount = float(approved_amount)
    except ValueError:
        report.approved_amount = report.total_amount

    report.status = ExpenseStatus.APPROVED
    report.reviewer_id = current_user.id
    report.reviewer_notes = request.form.get("reviewer_notes", "").strip()
    report.reviewed_at = datetime.utcnow()
    db.session.commit()
    send_approval_notification(report.employee, report)
    flash(f"Rendición #{report.id} aprobada. Se notificó al empleado.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/report/<int:report_id>/reject", methods=["POST"])
@login_required
@admin_required
def reject_report(report_id):
    report = ExpenseReport.query.get_or_404(report_id)
    reason = request.form.get("rejection_reason", "").strip()
    if not reason:
        flash("Debes indicar el motivo del rechazo.", "danger")
        return redirect(url_for("admin.view_report", report_id=report_id))
    report.status = ExpenseStatus.REJECTED
    report.reviewer_id = current_user.id
    report.rejection_reason = reason
    report.reviewed_at = datetime.utcnow()
    db.session.commit()
    send_rejection_notification(report.employee, report)
    flash(f"Rendición #{report.id} rechazada. Se notificó al empleado.", "info")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/report/<int:report_id>/mark-paid", methods=["POST"])
@login_required
@admin_required
def mark_paid(report_id):
    report = ExpenseReport.query.get_or_404(report_id)
    if report.status != ExpenseStatus.APPROVED:
        flash("Solo se pueden marcar como pagadas las rendiciones aprobadas.", "warning")
        return redirect(url_for("admin.dashboard"))
    report.status = ExpenseStatus.PAID
    report.paid_at = datetime.utcnow()
    db.session.commit()
    send_payment_notification(report.employee, report)
    flash(f"Rendición #{report.id} marcada como pagada. Se notificó al empleado.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.name).all()
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/users/new", methods=["GET", "POST"])
@login_required
@admin_required
def new_user():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if User.query.filter_by(email=email).first():
            flash("Ya existe un usuario con ese email.", "danger")
            return redirect(url_for("admin.new_user"))
        user = User(
            name=request.form.get("name", "").strip(),
            email=email,
            department=request.form.get("department", "").strip(),
            position=request.form.get("position", "").strip(),
            is_admin=bool(request.form.get("is_admin")),
        )
        user.set_password(request.form.get("password", ""))
        db.session.add(user)
        db.session.commit()
        flash(f"Usuario {user.name} creado correctamente.", "success")
        return redirect(url_for("admin.users"))
    return render_template("admin/new_user.html")


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("No puedes desactivar tu propia cuenta.", "warning")
        return redirect(url_for("admin.users"))
    user.is_active = not user.is_active
    db.session.commit()
    state = "activado" if user.is_active else "desactivado"
    flash(f"Usuario {user.name} {state}.", "info")
    return redirect(url_for("admin.users"))
