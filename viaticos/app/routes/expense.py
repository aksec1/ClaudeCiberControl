from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_from_directory, current_app
from flask_login import login_required, current_user
from app import db
from app.models.expense import ExpenseReport, ExpenseItem, ExpenseAttachment, ExpenseStatus, ExpenseType, TYPE_LABELS
from app.services.file_service import save_upload, delete_upload
from app.services.email_service import send_submission_confirmation
from datetime import date, datetime
import os

expense_bp = Blueprint("expense", __name__, url_prefix="/expense")


@expense_bp.route("/")
@login_required
def list_reports():
    query = ExpenseReport.query.filter_by(user_id=current_user.id)
    status_filter = request.args.get("status")
    if status_filter:
        query = query.filter_by(status=status_filter)
    reports = query.order_by(ExpenseReport.created_at.desc()).all()
    return render_template("expense/list.html", reports=reports, statuses=ExpenseStatus, status_filter=status_filter)


@expense_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_report():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("El título es obligatorio.", "danger")
            return redirect(url_for("expense.new_report"))
        report = ExpenseReport(
            user_id=current_user.id,
            title=title,
            description=request.form.get("description", "").strip(),
            travel_destination=request.form.get("travel_destination", "").strip(),
            travel_start=_parse_date(request.form.get("travel_start")),
            travel_end=_parse_date(request.form.get("travel_end")),
            status=ExpenseStatus.DRAFT,
        )
        db.session.add(report)
        db.session.commit()
        flash("Rendición creada. Ahora agrega los ítems de gasto.", "success")
        return redirect(url_for("expense.view_report", report_id=report.id))
    return render_template("expense/new.html")


@expense_bp.route("/<int:report_id>")
@login_required
def view_report(report_id):
    report = _get_report_or_404(report_id)
    expense_types = [(e.value, TYPE_LABELS[e]) for e in ExpenseType]
    return render_template("expense/view.html", report=report, expense_types=expense_types, today=date.today())


@expense_bp.route("/<int:report_id>/add-item", methods=["POST"])
@login_required
def add_item(report_id):
    report = _get_report_or_404(report_id)
    if report.status not in (ExpenseStatus.DRAFT, ExpenseStatus.REJECTED):
        flash("No se pueden modificar rendiciones enviadas.", "warning")
        return redirect(url_for("expense.view_report", report_id=report_id))

    description = request.form.get("description", "").strip()
    amount_str = request.form.get("amount", "0").replace(",", ".")
    expense_type = request.form.get("expense_type")
    expense_date_str = request.form.get("expense_date")

    if not description or not expense_date_str:
        flash("Descripción y fecha son obligatorios.", "danger")
        return redirect(url_for("expense.view_report", report_id=report_id))

    try:
        amount = float(amount_str)
        assert amount > 0
    except (ValueError, AssertionError):
        flash("El monto debe ser un número mayor a 0.", "danger")
        return redirect(url_for("expense.view_report", report_id=report_id))

    item = ExpenseItem(
        report_id=report_id,
        expense_type=expense_type,
        description=description,
        expense_date=_parse_date(expense_date_str),
        amount=amount,
        currency=request.form.get("currency", "CLP"),
        vendor=request.form.get("vendor", "").strip(),
        notes=request.form.get("notes", "").strip(),
    )
    db.session.add(item)
    db.session.flush()

    files = request.files.getlist("attachments")
    errors = []
    for f in files:
        if f and f.filename:
            result, err = save_upload(f, subfolder=f"report_{report_id}")
            if err:
                errors.append(err)
            else:
                attachment = ExpenseAttachment(item_id=item.id, **result)
                db.session.add(attachment)

    report.recalculate_total()
    db.session.commit()

    if errors:
        flash(f"Ítem guardado con advertencias: {'; '.join(errors)}", "warning")
    else:
        flash("Ítem agregado correctamente.", "success")
    return redirect(url_for("expense.view_report", report_id=report_id))


@expense_bp.route("/<int:report_id>/delete-item/<int:item_id>", methods=["POST"])
@login_required
def delete_item(report_id, item_id):
    report = _get_report_or_404(report_id)
    if report.status not in (ExpenseStatus.DRAFT, ExpenseStatus.REJECTED):
        flash("No se puede modificar esta rendición.", "warning")
        return redirect(url_for("expense.view_report", report_id=report_id))

    item = ExpenseItem.query.filter_by(id=item_id, report_id=report_id).first_or_404()
    for att in item.attachments:
        delete_upload(att.filename)
    db.session.delete(item)
    report.recalculate_total()
    db.session.commit()
    flash("Ítem eliminado.", "info")
    return redirect(url_for("expense.view_report", report_id=report_id))


@expense_bp.route("/<int:report_id>/submit", methods=["POST"])
@login_required
def submit_report(report_id):
    report = _get_report_or_404(report_id)
    if report.status not in (ExpenseStatus.DRAFT, ExpenseStatus.REJECTED):
        flash("Esta rendición ya fue enviada.", "warning")
        return redirect(url_for("expense.view_report", report_id=report_id))
    if report.items.count() == 0:
        flash("Debes agregar al menos un ítem antes de enviar.", "danger")
        return redirect(url_for("expense.view_report", report_id=report_id))

    report.status = ExpenseStatus.SUBMITTED
    report.submitted_at = datetime.utcnow()
    db.session.commit()
    send_submission_confirmation(current_user, report)
    flash("Rendición enviada correctamente. Recibirás un email de confirmación.", "success")
    return redirect(url_for("expense.list_reports"))


@expense_bp.route("/uploads/<path:filename>")
@login_required
def serve_upload(filename):
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    if not current_user.is_admin:
        parts = filename.split("/")
        if parts and parts[0].startswith("report_"):
            try:
                report_id = int(parts[0].replace("report_", ""))
                report = ExpenseReport.query.get_or_404(report_id)
                if report.user_id != current_user.id:
                    abort(403)
            except (ValueError, AttributeError):
                abort(403)
    return send_from_directory(upload_dir, filename)


def _get_report_or_404(report_id):
    report = ExpenseReport.query.get_or_404(report_id)
    if not current_user.is_admin and report.user_id != current_user.id:
        abort(403)
    return report


def _parse_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return None
