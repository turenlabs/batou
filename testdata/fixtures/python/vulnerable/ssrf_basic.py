# Vulnerable: SSRF via requests.get with user-controlled URL
# Expected: Taint sink match for py.requests.get (CWE-918)

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text


@app.route("/proxy")
def proxy():
    target = request.args.get("target")
    resp = requests.get(target, timeout=10)
    return jsonify({"status": resp.status_code, "body": resp.text[:1000]})


@app.route("/check-health")
def health_check():
    service_url = request.form.get("service_url")
    try:
        resp = requests.get(service_url, timeout=5)
        return jsonify({"healthy": resp.status_code == 200})
    except Exception as e:
        return jsonify({"healthy": False, "error": str(e)})


@app.route("/webhook-test", methods=["POST"])
def test_webhook():
    webhook_url = request.json.get("url")
    payload = request.json.get("payload", {})
    resp = requests.post(webhook_url, json=payload)
    return jsonify({"status": resp.status_code})
