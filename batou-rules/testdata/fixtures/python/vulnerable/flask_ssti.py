# Flask SSTI examples

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # Vulnerable: user input directly in template string
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


@app.route('/page')
def page():
    content = request.args.get('content')
    # Vulnerable: variable passed to render_template_string
    return render_template_string(content)


@app.route('/profile')
def profile():
    bio = request.form.get('bio')
    tmpl = "<div>%s</div>" % bio
    # Vulnerable: formatted string passed to render_template_string
    return render_template_string(tmpl)
