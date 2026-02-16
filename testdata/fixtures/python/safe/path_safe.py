# Safe: Path traversal prevention with realpath + startswith check
# Expected: No findings for BATOU-TRV-001

import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

UPLOAD_DIR = os.path.realpath("/var/uploads")
REPORT_DIR = os.path.realpath("/var/reports")


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    requested_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not requested_path.startswith(UPLOAD_DIR):
        abort(403)
    if not os.path.isfile(requested_path):
        abort(404)
    return send_file(requested_path)


@app.route("/report")
def report():
    name = request.args.get("name", "")
    safe_name = os.path.basename(name)
    file_path = os.path.realpath(os.path.join(REPORT_DIR, safe_name))
    if not file_path.startswith(REPORT_DIR):
        abort(403)
    with open(file_path) as f:
        return f.read()


@app.route("/avatar")
def avatar():
    user_file = request.args.get("file", "")
    if ".." in user_file or "/" in user_file:
        abort(400)
    safe_path = os.path.realpath(os.path.join("/uploads/avatars", user_file))
    if not safe_path.startswith("/uploads/avatars"):
        abort(403)
    return send_file(safe_path)
