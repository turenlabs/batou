# Safe: Jinja2 with autoescape enabled, no |safe filter on user input
# Expected: No findings for BATOU-SSTI-001

from flask import Flask, request, render_template_string, render_template
from markupsafe import escape

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # Safe: using render_template with a file (autoescape on by default)
    return render_template("greet.html", name=name)


@app.route("/profile")
def profile():
    bio = request.args.get("bio", "")
    # Safe: escape user input before embedding in template
    safe_bio = escape(bio)
    return render_template("profile.html", bio=safe_bio)


@app.route("/message")
def message():
    # Safe: render_template_string with autoescape and no |safe on user data
    msg = request.args.get("msg", "")
    template = "{% autoescape true %}<p>{{ message }}</p>{% endautoescape %}"
    return render_template_string(template, message=msg)
