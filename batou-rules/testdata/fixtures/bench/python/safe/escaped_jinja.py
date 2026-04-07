from flask import Flask, request, render_template, jsonify
from markupsafe import escape

app = Flask(__name__)

# SAFE: Jinja2 auto-escaping (default in Flask render_template)
@app.route("/profile/<username>")
def profile(username: str):
    return render_template("profile.html", username=username)


# SAFE: markupsafe.escape for manual HTML escaping
@app.route("/search")
def search():
    query = request.args.get("q", "")
    safe_query = escape(query)
    return jsonify({"query": str(safe_query), "results": []})


# SAFE: JSON response (no HTML rendering)
@app.route("/api/users")
def api_users():
    name = request.args.get("name", "")
    return jsonify({"name": name, "status": "active"})


# SAFE: render_template with variables (Jinja2 auto-escapes)
@app.route("/dashboard")
def dashboard():
    user_input = request.args.get("message", "")
    return render_template("dashboard.html", message=user_input, title="Dashboard")
