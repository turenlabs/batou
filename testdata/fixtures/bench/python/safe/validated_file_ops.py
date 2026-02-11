import os
from pathlib import Path
from flask import request, send_file, jsonify, abort

UPLOAD_DIR = Path("/var/www/uploads")
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".txt"}

# SAFE: Path resolved and validated with startswith check
def download_file():
    filename = request.args.get("name", "")
    resolved = (UPLOAD_DIR / filename).resolve()
    if not str(resolved).startswith(str(UPLOAD_DIR)):
        abort(403)
    if not resolved.exists():
        abort(404)
    return send_file(str(resolved))


# SAFE: os.path.basename strips traversal components
def serve_document():
    raw_name = request.args.get("doc", "")
    safe_name = os.path.basename(raw_name)
    full_path = UPLOAD_DIR / safe_name
    if not full_path.exists():
        abort(404)
    return send_file(str(full_path))


# SAFE: Extension allowlist validation
def upload_file():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "No file"}), 400
    ext = Path(uploaded.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "File type not allowed"}), 400
    safe_name = os.path.basename(uploaded.filename)
    dest = UPLOAD_DIR / safe_name
    uploaded.save(str(dest))
    return jsonify({"saved": safe_name})


# SAFE: os.path.realpath + startswith for directory containment
def list_directory():
    subdir = request.args.get("path", "")
    target = os.path.realpath(os.path.join(str(UPLOAD_DIR), subdir))
    if not target.startswith(str(UPLOAD_DIR)):
        abort(403)
    entries = os.listdir(target)
    return jsonify({"files": entries})
