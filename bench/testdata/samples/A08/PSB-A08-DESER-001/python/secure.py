# PSB-A08-DESER-001: User data deserialization
# CWE: CWE-502
# Expected: (none - secure)
from flask import Flask, request, jsonify
import json

app = Flask(__name__)

ALLOWED_KEYS = {"theme", "language", "timezone", "notifications", "font_size"}
VALID_THEMES = {"light", "dark", "system"}
VALID_LANGUAGES = {"en", "es", "fr", "de", "ja", "zh"}

@app.route("/api/preferences/import", methods=["POST"])
def import_preferences():
    data = request.get_json()
    raw = data.get("preferences")
    if not raw:
        return jsonify({"error": "preferences data is required"}), 400

    try:
        if isinstance(raw, str):
            preferences = json.loads(raw)
        else:
            preferences = raw
    except (json.JSONDecodeError, TypeError):
        return jsonify({"error": "invalid JSON preferences"}), 400

    safe_prefs = {k: v for k, v in preferences.items() if k in ALLOWED_KEYS}

    user_id = data.get("user_id")
    # db.execute("UPDATE users SET prefs = ? WHERE id = ?", (json.dumps(safe_prefs), user_id))

    return jsonify({"status": "imported", "preferences": safe_prefs})

if __name__ == "__main__":
    app.run()
