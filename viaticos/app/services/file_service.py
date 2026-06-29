import os
import uuid
from werkzeug.utils import secure_filename
from flask import current_app

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "pdf"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file, subfolder="general"):
    if not file or not allowed_file(file.filename):
        return None, "Tipo de archivo no permitido. Use imágenes (PNG, JPG, GIF) o PDF."

    ext = file.filename.rsplit(".", 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"

    upload_dir = os.path.join(current_app.config["UPLOAD_FOLDER"], subfolder)
    os.makedirs(upload_dir, exist_ok=True)

    path = os.path.join(upload_dir, unique_name)
    file.save(path)

    file.seek(0, os.SEEK_END)
    size = file.tell()

    return {
        "filename": os.path.join(subfolder, unique_name),
        "original_filename": secure_filename(file.filename),
        "file_type": ext,
        "file_size": size,
    }, None


def delete_upload(filename):
    try:
        path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(path):
            os.remove(path)
        return True
    except Exception as e:
        current_app.logger.error(f"Error eliminando archivo {filename}: {e}")
        return False
