from flask import current_app, render_template_string
from flask_mail import Message
from app import mail


TEMPLATE_BASE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }}
    .container {{ max-width: 600px; margin: 30px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
    .header {{ background: #1a3c5e; color: #fff; padding: 24px 32px; }}
    .header h1 {{ margin: 0; font-size: 22px; }}
    .body {{ padding: 28px 32px; color: #333; line-height: 1.6; }}
    .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
    .badge-success {{ background: #d4edda; color: #155724; }}
    .badge-danger {{ background: #f8d7da; color: #721c24; }}
    .badge-info {{ background: #d1ecf1; color: #0c5460; }}
    .detail-box {{ background: #f8f9fa; border-left: 4px solid #1a3c5e; padding: 16px; margin: 16px 0; border-radius: 0 6px 6px 0; }}
    .footer {{ background: #f4f4f4; padding: 16px 32px; text-align: center; font-size: 12px; color: #888; }}
    .btn {{ display: inline-block; padding: 10px 24px; background: #1a3c5e; color: #fff; text-decoration: none; border-radius: 4px; margin-top: 12px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header"><h1>{{ company }} — Rendición de Gastos</h1></div>
    <div class="body">{{ content }}</div>
    <div class="footer">Este es un mensaje automático, no responda a este correo.</div>
  </div>
</body>
</html>
"""


def _send(to, subject, html_content):
    try:
        company = current_app.config.get("COMPANY_NAME", "Mi Empresa")
        html = render_template_string(TEMPLATE_BASE, company=company, content=html_content)
        msg = Message(subject=subject, recipients=[to], html=html)
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Error enviando email a {to}: {e}")
        return False


def send_submission_confirmation(user, report):
    content = f"""
    <p>Hola <strong>{user.name}</strong>,</p>
    <p>Tu rendición de gastos ha sido enviada correctamente y está pendiente de revisión.</p>
    <div class="detail-box">
      <strong>Rendición:</strong> {report.title}<br>
      <strong>Monto total:</strong> ${report.total_amount:,.0f} {''}<br>
      <strong>N° de ítems:</strong> {report.items.count()}<br>
      <strong>Estado:</strong> <span class="badge badge-info">Enviado para revisión</span>
    </div>
    <p>Te notificaremos cuando haya novedades sobre tu rendición.</p>
    """
    return _send(user.email, f"[Rendición #{report.id}] Recibida exitosamente", content)


def send_approval_notification(user, report):
    content = f"""
    <p>Hola <strong>{user.name}</strong>,</p>
    <p>¡Buenas noticias! Tu rendición de gastos ha sido <strong>aprobada</strong>.</p>
    <div class="detail-box">
      <strong>Rendición:</strong> {report.title}<br>
      <strong>Monto aprobado:</strong> ${report.approved_amount:,.0f}<br>
      <strong>Estado:</strong> <span class="badge badge-success">Aprobado</span><br>
      {"<strong>Notas del revisor:</strong> " + report.reviewer_notes if report.reviewer_notes else ""}
    </div>
    <p>El monto será acreditado en tu cuenta bancaria registrada en un plazo de 2–3 días hábiles.</p>
    <p><strong>Cuenta:</strong> {user.bank_name or "—"} {user.bank_account or "—"}</p>
    """
    return _send(user.email, f"[Rendición #{report.id}] Aprobada — Pago en proceso", content)


def send_rejection_notification(user, report):
    content = f"""
    <p>Hola <strong>{user.name}</strong>,</p>
    <p>Lamentablemente tu rendición de gastos ha sido <strong>rechazada</strong> o requiere correcciones.</p>
    <div class="detail-box">
      <strong>Rendición:</strong> {report.title}<br>
      <strong>Estado:</strong> <span class="badge badge-danger">Rechazado</span><br>
      <strong>Motivo:</strong><br>
      {report.rejection_reason or "Sin motivo especificado."}
    </div>
    <p>Por favor, revisa los detalles de tu rendición, corrige los ítems señalados y vuelve a enviarla.</p>
    <p>Si tienes dudas, comunícate con el área de administración.</p>
    """
    return _send(user.email, f"[Rendición #{report.id}] Requiere correcciones", content)


def send_payment_notification(user, report):
    content = f"""
    <p>Hola <strong>{user.name}</strong>,</p>
    <p>Tu reembolso ha sido <strong>procesado y acreditado</strong> exitosamente.</p>
    <div class="detail-box">
      <strong>Rendición:</strong> {report.title}<br>
      <strong>Monto acreditado:</strong> ${report.approved_amount:,.0f}<br>
      <strong>Cuenta:</strong> {user.bank_name or "—"} — {user.bank_account or "—"}<br>
      <strong>Estado:</strong> <span class="badge badge-success">Pagado</span>
    </div>
    <p>Si no ves el depósito en 24 horas, contacta al área de administración.</p>
    """
    return _send(user.email, f"[Rendición #{report.id}] Dinero acreditado en tu cuenta", content)
