# Vulnerable: Server-side template injection via render_template_string
# Expected: BATOU-INJ-005 (Template Injection)

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/render")
def render_page():
    template = request.args.get("template")
    return render_template_string(template)


@app.route("/greeting")
def greeting():
    name = request.args.get("name", "World")
    user_template = request.args.get("tpl", "Hello, {{ name }}!")
    return render_template_string(user_template, name=name)


@app.route("/email-preview", methods=["POST"])
def email_preview():
    body_template = request.form.get("body")
    context = {
        "user": request.form.get("user"),
        "subject": request.form.get("subject"),
    }
    rendered = render_template_string(body_template, **context)
    return rendered


@app.route("/report")
def report():
    report_tpl = request.args.get("report_template")
    data = {"title": "Monthly Report", "date": "2024-01-01"}
    return render_template_string(report_tpl, **data)
