"""
Script de inicialización de la base de datos.
Crea tablas y un usuario administrador por defecto.
Uso: python init_db.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from app.models.user import User
from app.models.expense import ExpenseReport, ExpenseItem, ExpenseAttachment


def init():
    app = create_app()
    with app.app_context():
        db.create_all()
        print("[OK] Tablas creadas.")

        admin_email = os.getenv("ADMIN_EMAIL", "admin@empresa.com")
        if not User.query.filter_by(email=admin_email).first():
            admin = User(
                name="Administrador",
                email=admin_email,
                department="Administración",
                position="Administrador del Sistema",
                is_admin=True,
                is_active=True,
            )
            admin.set_password("Admin1234!")
            db.session.add(admin)
            db.session.commit()
            print(f"[OK] Usuario admin creado: {admin_email} / Admin1234!")
            print("     IMPORTANTE: cambia la contraseña en el primer ingreso.")
        else:
            print(f"[--] Usuario admin ya existe: {admin_email}")


if __name__ == "__main__":
    init()
