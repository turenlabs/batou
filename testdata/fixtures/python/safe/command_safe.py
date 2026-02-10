# Safe: subprocess.run with list arguments and shell=False
# Expected: No findings for GTSS-INJ-002

import subprocess
import shlex
from flask import Flask, request

app = Flask(__name__)

ALLOWED_HOSTS = {"example.com", "test.internal"}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:
        return "Invalid host", 400
    result = subprocess.run(
        ["ping", "-c", "3", host],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


@app.route("/convert")
def convert():
    filename = request.args.get("file", "")
    if not filename.isalnum():
        return "Invalid filename", 400
    result = subprocess.run(
        ["convert", f"/uploads/{filename}", "-resize", "100x100", "/tmp/out.png"],
        capture_output=True,
        text=True,
    )
    return "Converted" if result.returncode == 0 else "Failed"


@app.route("/disk-usage")
def disk_usage():
    result = subprocess.run(
        ["df", "-h"],
        capture_output=True,
        text=True,
    )
    return result.stdout
