# Vulnerable: Log injection with unsanitized user input
# Expected: BATOU-LOG-001 (UnsanitizedLogInput)

import logging
from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    logger.info(f"Login attempt for user: {request.form['username']}")

    if authenticate(username, request.form.get("password")):
        logger.info(f"Login successful: {request.form['username']}")
        return "OK"
    else:
        logger.warning(f"Failed login for: {request.form['username']}")
        return "Unauthorized", 401


@app.route("/api/data", methods=["POST"])
def process():
    logging.info(f"Processing request from: {request.form['user_id']}")
    data = request.json
    logging.debug(f"Request payload: {request.data}")
    return "OK"


@app.route("/search")
def search():
    query = request.args.get("q")
    logger.info(f"Search query: {request.args['q']}")
    return "Results"


def authenticate(username, password):
    return True
