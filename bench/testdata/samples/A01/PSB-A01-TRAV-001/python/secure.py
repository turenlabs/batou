# PSB-A01-TRAV-001: File download endpoint
# CWE: CWE-22, CWE-23
# Expected: (none - secure)
from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)
UPLOAD_DIR = "/var/app/uploads"

@app.route("/api/download")
def download():
    filename = request.args.get("filename")
    if not filename:
        return {"error": "filename is required"}, 400

    safe_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not safe_path.startswith(os.path.realpath(UPLOAD_DIR)):
        abort(403)

    if not os.path.isfile(safe_path):
        abort(404)

    return send_file(safe_path)

if __name__ == "__main__":
    app.run()
