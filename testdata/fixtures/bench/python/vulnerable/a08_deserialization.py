# Source: CWE-502 - Deserialization of untrusted data via pickle
# Expected: BATOU-GEN-002 (Unsafe Deserialization - pickle.loads)
# OWASP: A08:2021 - Software and Data Integrity Failures

import pickle
import base64
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/session/restore', methods=['POST'])
def restore_session():
    session_data = request.form.get('session', '')
    decoded = base64.b64decode(session_data)
    session = pickle.loads(decoded)
    return jsonify({'user': session.get('username'), 'role': session.get('role')})

@app.route('/api/config/import', methods=['POST'])
def import_config():
    config_text = request.data.decode('utf-8')
    config = yaml.load(config_text, Loader=yaml.Loader)
    return jsonify({'keys': list(config.keys())})

@app.route('/api/cache/get')
def get_cached():
    import redis
    r = redis.Redis()
    key = request.args.get('key', '')
    cached = r.get(key)
    if cached:
        return jsonify(pickle.loads(cached))
    return jsonify({'error': 'Not found'}), 404
