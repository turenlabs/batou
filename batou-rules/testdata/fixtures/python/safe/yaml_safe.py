# Safe: YAML safe_load for deserialization
# Expected: No findings for CWE-502 yaml deserialization

import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def upload_config():
    yaml_content = request.data.decode("utf-8")
    config = yaml.safe_load(yaml_content)
    return jsonify(config)


@app.route("/import-settings", methods=["POST"])
def import_settings():
    file = request.files.get("config_file")
    content = file.read()
    settings = yaml.safe_load(content)
    return jsonify({"status": "ok", "settings": settings})


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data(as_text=True)
    data = yaml.safe_load(payload)
    return jsonify({"received": True})


@app.route("/multi-doc", methods=["POST"])
def multi_doc():
    content = request.data.decode("utf-8")
    docs = list(yaml.safe_load_all(content))
    return jsonify({"documents": docs})
