from app import db
from datetime import datetime
import enum


class ExpenseStatus(str, enum.Enum):
    DRAFT = "borrador"
    SUBMITTED = "enviado"
    UNDER_REVIEW = "en_revision"
    APPROVED = "aprobado"
    REJECTED = "rechazado"
    PAID = "pagado"


class ExpenseType(str, enum.Enum):
    VIATICO = "viatico"
    LUNCH = "almuerzo"
    TRANSPORT = "transporte"
    ACCOMMODATION = "alojamiento"
    OTHER = "otro"


STATUS_LABELS = {
    ExpenseStatus.DRAFT: "Borrador",
    ExpenseStatus.SUBMITTED: "Enviado",
    ExpenseStatus.UNDER_REVIEW: "En Revisión",
    ExpenseStatus.APPROVED: "Aprobado",
    ExpenseStatus.REJECTED: "Rechazado",
    ExpenseStatus.PAID: "Pagado",
}

TYPE_LABELS = {
    ExpenseType.VIATICO: "Viático",
    ExpenseType.LUNCH: "Almuerzo",
    ExpenseType.TRANSPORT: "Transporte",
    ExpenseType.ACCOMMODATION: "Alojamiento",
    ExpenseType.OTHER: "Otro",
}


class ExpenseReport(db.Model):
    __tablename__ = "expense_reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    travel_destination = db.Column(db.String(200))
    travel_start = db.Column(db.Date)
    travel_end = db.Column(db.Date)
    total_amount = db.Column(db.Numeric(12, 2), default=0)
    approved_amount = db.Column(db.Numeric(12, 2))
    status = db.Column(db.String(20), default=ExpenseStatus.DRAFT)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    reviewer_notes = db.Column(db.Text)
    rejection_reason = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime)
    reviewed_at = db.Column(db.DateTime)
    paid_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = db.relationship("ExpenseItem", backref="report", lazy="dynamic", cascade="all, delete-orphan")
    reviewer = db.relationship("User", foreign_keys=[reviewer_id])

    @property
    def status_label(self):
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def status_badge(self):
        badges = {
            ExpenseStatus.DRAFT: "secondary",
            ExpenseStatus.SUBMITTED: "info",
            ExpenseStatus.UNDER_REVIEW: "warning",
            ExpenseStatus.APPROVED: "success",
            ExpenseStatus.REJECTED: "danger",
            ExpenseStatus.PAID: "primary",
        }
        return badges.get(self.status, "secondary")

    def recalculate_total(self):
        self.total_amount = sum(item.amount for item in self.items)
        db.session.commit()

    def __repr__(self):
        return f"<ExpenseReport {self.id} - {self.title}>"


class ExpenseItem(db.Model):
    __tablename__ = "expense_items"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("expense_reports.id"), nullable=False)
    expense_type = db.Column(db.String(30), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    expense_date = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency = db.Column(db.String(5), default="CLP")
    vendor = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    attachments = db.relationship("ExpenseAttachment", backref="item", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def type_label(self):
        return TYPE_LABELS.get(self.expense_type, self.expense_type)

    def __repr__(self):
        return f"<ExpenseItem {self.id} - {self.expense_type} ${self.amount}>"


class ExpenseAttachment(db.Model):
    __tablename__ = "expense_attachments"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("expense_items.id"), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    original_filename = db.Column(db.String(300), nullable=False)
    file_type = db.Column(db.String(10))
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_image(self):
        return self.file_type in ("jpg", "jpeg", "png", "gif", "webp")

    @property
    def is_pdf(self):
        return self.file_type == "pdf"

    def __repr__(self):
        return f"<ExpenseAttachment {self.filename}>"
