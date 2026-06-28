from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.expense import ExpenseReport, ExpenseStatus
from sqlalchemy import func
from app import db

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def home():
    if current_user.is_admin:
        pending = ExpenseReport.query.filter(
            ExpenseReport.status.in_([ExpenseStatus.SUBMITTED, ExpenseStatus.UNDER_REVIEW])
        ).count()
        total_approved = db.session.query(func.sum(ExpenseReport.approved_amount)).filter(
            ExpenseReport.status == ExpenseStatus.PAID
        ).scalar() or 0
        recent = ExpenseReport.query.order_by(ExpenseReport.updated_at.desc()).limit(10).all()
        stats = {
            "pending": pending,
            "total_approved": total_approved,
            "recent": recent,
            "all_reports": ExpenseReport.query.count(),
        }
    else:
        my_reports = ExpenseReport.query.filter_by(user_id=current_user.id)
        stats = {
            "draft": my_reports.filter_by(status=ExpenseStatus.DRAFT).count(),
            "submitted": my_reports.filter(
                ExpenseReport.status.in_([ExpenseStatus.SUBMITTED, ExpenseStatus.UNDER_REVIEW])
            ).count(),
            "approved": my_reports.filter_by(status=ExpenseStatus.APPROVED).count(),
            "paid": my_reports.filter_by(status=ExpenseStatus.PAID).count(),
            "rejected": my_reports.filter_by(status=ExpenseStatus.REJECTED).count(),
            "recent": my_reports.order_by(ExpenseReport.updated_at.desc()).limit(5).all(),
            "total_paid": db.session.query(func.sum(ExpenseReport.approved_amount)).filter(
                ExpenseReport.user_id == current_user.id,
                ExpenseReport.status == ExpenseStatus.PAID
            ).scalar() or 0,
        }
    return render_template("dashboard/home.html", stats=stats)
