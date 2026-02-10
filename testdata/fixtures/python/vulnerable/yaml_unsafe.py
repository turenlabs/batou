# Vulnerable: Unsafe YAML deserialization without SafeLoader
# Expected: Taint sink match for py.yaml.load (CWE-502)

import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def upload_config():
    yaml_content = request.data.decode("utf-8")
    config = yaml.load(yaml_content)
    return jsonify(config)


@app.route("/import-settings", methods=["POST"])
def import_settings():
    file = request.files.get("config_file")
    content = file.read()
    settings = yaml.load(content)
    return jsonify({"status": "ok", "settings": settings})


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data(as_text=True)
    data = yaml.load(payload)
    return jsonify({"received": True})
