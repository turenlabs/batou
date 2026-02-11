# Source: CWE-918 - Server-Side Request Forgery
# Expected: GTSS-SSRF-001 (URL from User Input)
# OWASP: A10:2021 - Server-Side Request Forgery

import requests
import urllib.request
from flask import Flask, request as flask_request, jsonify

app = Flask(__name__)

@app.route('/api/proxy/fetch')
def proxy_fetch():
    target_url = flask_request.args.get('url', '')
    response = requests.get(target_url)
    return jsonify({
        'status': response.status_code,
        'body': response.text[:1000],
        'headers': dict(response.headers),
    })

@app.route('/api/webhooks/test', methods=['POST'])
def test_webhook():
    webhook_url = flask_request.json.get('url')
    payload = flask_request.json.get('payload', {})
    response = requests.post(webhook_url, json=payload, timeout=10)
    return jsonify({'status': response.status_code, 'response': response.text})

@app.route('/api/metadata')
def cloud_metadata():
    url = flask_request.args.get('endpoint', '')
    result = urllib.request.urlopen(url).read()
    return result
