# Vulnerable: Command injection via os.system and subprocess with shell=True
# Expected: GTSS-INJ-002 (Command Injection)

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 3 " + host)
    return "Done"


@app.route("/convert")
def convert():
    filename = request.args.get("file")
    os.popen("convert /uploads/" + filename + " /tmp/out.png")
    return "Converted"


@app.route("/compress")
def compress():
    directory = request.form.get("dir")
    subprocess.call("tar -czf /tmp/archive.tar.gz " + directory, shell=True)
    return "Compressed"


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain")
    result = subprocess.check_output(f"nslookup {domain}", shell=True)
    return result


@app.route("/process")
def process_file():
    path = request.args.get("path")
    subprocess.run(f"cat {path} | wc -l", shell=True, capture_output=True)
    return "Processed"
