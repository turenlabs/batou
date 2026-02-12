# PSB-A08-DESER-001: User data deserialization
# CWE: CWE-502
# Expected: GTSS-INJ-010
from flask import Flask, request, jsonify
import pickle
import base64

app = Flask(__name__)

@app.route("/api/preferences/import", methods=["POST"])
def import_preferences():
    data = request.get_json()
    encoded = data.get("preferences")
    if not encoded:
        return jsonify({"error": "preferences data is required"}), 400

    try:
        raw = base64.b64decode(encoded)
        preferences = pickle.loads(raw)
    except Exception:
        return jsonify({"error": "invalid preferences data"}), 400

    # Apply preferences to user account
    user_id = data.get("user_id")
    # db.execute("UPDATE users SET prefs = ? WHERE id = ?", (json.dumps(preferences), user_id))

    return jsonify({"status": "imported", "preferences": preferences})

if __name__ == "__main__":
    app.run()
