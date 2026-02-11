# Source: CVE-2022-42889 - Apache Commons Text (adapted to Python os.system)
# Expected: GTSS-INJ-002 (Command Injection via os.system/subprocess)
# OWASP: A03:2021 - Injection (OS Command Injection)

import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/tools/dns')
def dns_lookup():
    hostname = request.args.get('host', '')
    result = os.popen(f"nslookup {hostname}").read()
    return jsonify({'result': result})

@app.route('/api/tools/whois')
def whois_lookup():
    domain = request.args.get('domain', '')
    result = subprocess.check_output(f"whois {domain}", shell=True)
    return jsonify({'result': result.decode()})

@app.route('/api/reports/generate')
def generate_report():
    template = request.args.get('template', 'default')
    output_format = request.args.get('format', 'pdf')
    os.system(f"wkhtmltopdf /templates/{template}.html /tmp/report.{output_format}")
    return jsonify({'status': 'generated'})
