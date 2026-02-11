# Source: PayloadsAllTheThings - Jinja2 SSTI
# Expected: GTSS-INJ-005 (Template Injection)
# OWASP: A03:2021 - Injection (Server-Side Template Injection)

from flask import Flask, request, render_template_string
from jinja2 import Template

app = Flask(__name__)

@app.route('/greeting')
def greeting():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1><p>Welcome to our site.</p>"
    return render_template_string(template)

@app.route('/invoice')
def invoice():
    company = request.form.get('company', '')
    amount = request.form.get('amount', '0')
    tmpl = Template("Invoice for {{ company }}: $" + amount)
    return tmpl.render(company=company)

@app.route('/error')
def custom_error():
    page = request.args.get('page', 'unknown')
    error_html = "<h1>404</h1><p>Page %s not found</p>" % page
    return render_template_string(error_html)
