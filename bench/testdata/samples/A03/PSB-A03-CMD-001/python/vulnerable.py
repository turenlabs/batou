# PSB-A03-CMD-001: Deployment script runner
# CWE: CWE-78
# Expected: GTSS-INJ-005, GTSS-INJ-006
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route("/api/deploy", methods=["POST"])
def deploy():
    data = request.get_json()
    service = data.get("service")
    env = data.get("environment")

    if env not in ("staging", "production"):
        return jsonify({"error": "invalid environment"}), 400

    cmd = f"/opt/deploy/run.sh {service} {env}"
    output = os.popen(cmd).read()

    return jsonify({"status": "deployed", "output": output})

if __name__ == "__main__":
    app.run()
