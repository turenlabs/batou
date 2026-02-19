# Safe: Structured logging with sanitized input fields
# Expected: No findings for BATOU-LOG-001

import logging
import re
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


def sanitize_log(value):
    """Remove newlines and control characters from log input."""
    return re.sub(r"[\r\n\t]", "_", str(value))[:200]


@app.route("/login", methods=["POST"])
def login():
    username = sanitize_log(request.form.get("username", ""))
    action = sanitize_log(request.form.get("action", ""))

    # Safe: parameterized logging with sanitized values
    logger.info("Login attempt: username=%s action=%s ip=%s",
                username, action, request.remote_addr)

    logger.warning("Failed login: username=%s ip=%s",
                   username, request.remote_addr)
    return "OK"


@app.route("/search")
def search():
    query = sanitize_log(request.args.get("q", ""))
    # Safe: structured log format, sanitized input
    logger.info("Search query: q=%s", query)
    return "OK"
