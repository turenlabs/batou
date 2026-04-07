# Flask path traversal examples

from flask import Flask, request, send_file, send_from_directory

app = Flask(__name__)


@app.route('/download')
def download():
    filename = request.args.get('file')
    # Vulnerable: user-controlled path in send_file
    return send_file(filename)


@app.route('/files/<path:name>')
def serve_file(name):
    # Vulnerable: variable passed to send_file
    return send_file(name)


@app.route('/uploads')
def uploads():
    fname = request.args.get('name')
    # Vulnerable: user input in send_from_directory
    return send_from_directory('/uploads', request.args.get('name'))
