# PSB-A01-TRAV-001: File download endpoint
# CWE: CWE-22, CWE-23
# Expected: BATOU-TRAV-001, BATOU-TRAV-003
from flask import Flask, request, send_file
import os

app = Flask(__name__)
UPLOAD_DIR = "/var/app/uploads"

@app.route("/api/download")
def download():
    filename = request.args.get("filename")
    if not filename:
        return {"error": "filename is required"}, 400

    filepath = os.path.join(UPLOAD_DIR, filename)
    return send_file(filepath)

if __name__ == "__main__":
    app.run()
