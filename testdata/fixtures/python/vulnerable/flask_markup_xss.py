# Flask Markup XSS examples

from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.route('/comment')
def comment():
    text = request.args.get('text')
    # Vulnerable: user input wrapped in Markup
    return Markup(text)


@app.route('/profile')
def profile():
    bio = request.form.get('bio')
    # Vulnerable: Markup with f-string containing user input
    html = Markup(f"<div class='bio'>{bio}</div>")
    return html


@app.route('/message')
def message():
    msg = request.args.get('msg')
    # Vulnerable: Markup with string concatenation
    html = Markup("<p>" + msg + "</p>")
    return html
