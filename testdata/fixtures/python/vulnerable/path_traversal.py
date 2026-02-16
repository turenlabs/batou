# Vulnerable: Path traversal via open() with user-controlled path
# Expected: BATOU-TRV-001 (Path Traversal)

import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/uploads"


@app.route("/download")
def download():
    filename = request.args.get("file")
    file_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(file_path)


@app.route("/read")
def read_file():
    path = request.args.get("path")
    with open(os.path.join("/var/data", path)) as f:
        content = f.read()
    return content


@app.route("/avatar")
def avatar():
    user_file = request.args['file']
    return send_file("/uploads/avatars/" + user_file)


@app.route("/report")
def report():
    name = request.args.get("name")
    file_path = os.path.join("/var/reports", name)
    with open(file_path) as f:
        return f.read()
