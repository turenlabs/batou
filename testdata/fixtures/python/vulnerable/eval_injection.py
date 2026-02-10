# Vulnerable: Code injection via eval() with user input
# Expected: GTSS-INJ-003 (Code Injection)

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    result = eval(expression)
    return jsonify({"result": result})


@app.route("/filter", methods=["POST"])
def dynamic_filter():
    filter_expr = request.form.get("filter")
    data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    filtered = eval(f"[x for x in data if {filter_expr}]")
    return jsonify({"filtered": filtered})


@app.route("/transform", methods=["POST"])
def transform():
    code = request.form.get("code")
    data = request.json.get("data", [])
    exec(code)
    return jsonify({"status": "executed"})


@app.route("/config", methods=["POST"])
def set_config():
    key = request.form.get("key")
    value = request.form.get("value")
    eval(f"config.{key} = {value}")
    return "OK"
