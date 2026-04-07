# Flask misconfiguration examples

from flask import Flask

app = Flask(__name__)

# Vulnerable: hardcoded secret key
app.secret_key = 'super-secret-key-123'

# Vulnerable: debug mode
app.run(debug=True)

# Vulnerable: session cookie insecure
app.config['SESSION_COOKIE_SECURE'] = False


@app.route('/')
def index():
    return 'Hello World'


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
