# Safe: Jinja2 autoescape enabled, proper template rendering
# Expected: No findings for BATOU-XSS-004 or BATOU-XSS-008

from flask import Flask, request, render_template
from markupsafe import escape
import html

app = Flask(__name__)


@app.route("/comment")
def show_comment():
    comment = request.args.get("text", "")
    escaped = escape(comment)
    return render_template("comment.html", comment=escaped)


@app.route("/profile")
def profile():
    bio = request.form.get("bio", "")
    safe_bio = html.escape(bio)
    return render_template("profile.html", bio=safe_bio)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return render_template("search.html", query=query)


@app.route("/greeting")
def greeting():
    name = request.args.get("name", "Guest")
    escaped_name = escape(name)
    return render_template("greeting.html", name=escaped_name)
