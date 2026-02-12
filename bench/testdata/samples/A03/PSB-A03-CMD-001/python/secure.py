# PSB-A03-CMD-001: Deployment script runner
# CWE: CWE-78
# Expected: (none - secure)
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

ALLOWED_SERVICES = {"api", "web", "worker", "scheduler"}

@app.route("/api/deploy", methods=["POST"])
def deploy():
    data = request.get_json()
    service = data.get("service")
    env = data.get("environment")

    if env not in ("staging", "production"):
        return jsonify({"error": "invalid environment"}), 400
    if service not in ALLOWED_SERVICES:
        return jsonify({"error": "unknown service"}), 400

    result = subprocess.run(
        ["/opt/deploy/run.sh", service, env],
        capture_output=True, text=True, timeout=120,
    )
    return jsonify({"status": "deployed", "output": result.stdout})

if __name__ == "__main__":
    app.run()
