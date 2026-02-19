# Safe: URL allowlist validation before making HTTP requests
# Expected: No findings for BATOU-SSRF-001

import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com", "service.internal"}


@app.route("/fetch")
def fetch_url():
    target = request.args.get("url", "")
    parsed = urlparse(target)

    # Validate host against allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        return jsonify({"error": "host not allowed"}), 403

    # Safe: only allowlisted hosts are fetched
    resp = requests.get(target, timeout=10)
    return resp.text


@app.route("/api-proxy")
def api_proxy():
    endpoint = request.args.get("endpoint", "")

    # Safe: hardcoded base URL, only path is user-controlled
    base = "https://api.example.com"
    if not endpoint.startswith("/"):
        return "Invalid endpoint", 400

    # Strip path traversal
    clean = endpoint.replace("..", "")
    resp = requests.get(f"{base}{clean}", timeout=10)
    return resp.json()
