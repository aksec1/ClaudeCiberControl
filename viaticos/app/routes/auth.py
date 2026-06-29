from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        user = User.query.filter_by(email=email, is_active=True).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.home"))
        flash("Credenciales incorrectas. Verifica tu email y contraseña.", "danger")
    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.name = request.form.get("name", current_user.name).strip()
        current_user.department = request.form.get("department", "").strip()
        current_user.position = request.form.get("position", "").strip()
        current_user.bank_account = request.form.get("bank_account", "").strip()
        current_user.bank_name = request.form.get("bank_name", "").strip()
        new_password = request.form.get("new_password", "").strip()
        if new_password:
            if len(new_password) < 8:
                flash("La contraseña debe tener al menos 8 caracteres.", "danger")
                return redirect(url_for("auth.profile"))
            current_user.set_password(new_password)
        db.session.commit()
        flash("Perfil actualizado correctamente.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("auth/profile.html")
