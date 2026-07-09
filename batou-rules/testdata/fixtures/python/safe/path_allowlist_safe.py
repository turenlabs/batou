# Safe: allowlist containment guard before open() (pyast-fpr).
# The requested name is validated against a fixed allowlist set before reaching
# the file sink, so path traversal is structurally impossible. The blind AST
# path-traversal signal (BATOU-PYAST-004 / CWE-22) must be suppressed here; the
# taint layer already clears the variable via detectAllowlistCheck.
# Expected: No findings for BATOU-PYAST-004.

from flask import Flask, request

app = Flask(__name__)

ALLOWED = {"a.txt", "b.txt", "c.txt"}


@app.route("/read")
def read_file():
    p = request.args.get("f")
    if p in ALLOWED:
        with open(p) as fh:
            return fh.read()
    return "denied"
