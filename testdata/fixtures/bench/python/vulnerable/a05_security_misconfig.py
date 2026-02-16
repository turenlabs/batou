# Source: CWE-16 - Security misconfiguration in Flask/Django
# Expected: BATOU-GEN-001 (Debug Mode Enabled), BATOU-AUTH-003 (CORS Wildcard)
# OWASP: A05:2021 - Security Misconfiguration

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'development-key'
app.config['TESTING'] = True

CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.errorhandler(500)
def internal_error(error):
    import traceback
    return f"<pre>{traceback.format_exc()}</pre>", 500

@app.route('/api/debug/config')
def show_config():
    config_items = {k: str(v) for k, v in app.config.items()}
    return config_items

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
