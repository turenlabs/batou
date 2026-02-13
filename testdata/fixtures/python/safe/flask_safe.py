# Safe Flask usage for testing

from flask import Flask, request, render_template, send_from_directory
from markupsafe import escape
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

# Safe: secret key from environment
app.secret_key = os.environ.get('SECRET_KEY')


@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    # Safe: using render_template with file, data as context
    return render_template('greet.html', name=name)


@app.route('/download')
def download():
    filename = request.args.get('file')
    # Safe: secure_filename + fixed directory
    safe_name = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_DIR'], safe_name)


@app.route('/comment')
def comment():
    text = request.args.get('text')
    # Safe: escaping user input
    safe_text = escape(text)
    return render_template('comment.html', text=safe_text)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
