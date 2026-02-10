# Vulnerable: XSS via Markup() and |safe on user input
# Expected: GTSS-XSS-008 (ServerSideRenderingXSS), GTSS-XSS-004 (UnescapedTemplateOutput)

from flask import Flask, request, render_template_string
from markupsafe import Markup

app = Flask(__name__)


@app.route("/comment")
def show_comment():
    comment = request.args.get("text", "")
    safe_comment = Markup(comment)
    return render_template_string("<div>{{ comment }}</div>", comment=safe_comment)


@app.route("/profile")
def profile():
    bio = request.form.get("bio", "")
    html = Markup("<div class='bio'>%s</div>") % bio
    return html


@app.route("/preview")
def preview():
    content = request.args.get("content", "")
    template = "<html><body>{{ content | safe }}</body></html>"
    return render_template_string(template, content=content)


@app.route("/greeting")
def greeting():
    name = request.args.get("name", "Guest")
    return Markup.format("<h1>Welcome, {name}!</h1>", name=name)
