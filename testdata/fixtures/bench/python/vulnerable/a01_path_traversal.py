# Source: OWASP Juice Shop - File access with path traversal
# Expected: BATOU-TRV-001 (Path Traversal via user input in file operations)
# OWASP: A01:2021 - Broken Access Control (Path Traversal)

import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
UPLOAD_DIR = '/var/uploads'

@app.route('/api/files/download')
def download_file():
    filename = request.args.get('file', '')
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath)

@app.route('/api/files/read')
def read_file():
    path = request.args.get('path', '')
    with open(path, 'r') as f:
        content = f.read()
    return content

@app.route('/api/logs/view')
def view_log():
    logname = request.args.get('name', 'app.log')
    log_path = f"/var/log/{logname}"
    with open(log_path) as f:
        return f.read()
