from flask import request, jsonify
from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
db = client['myapp']

# VULNERABLE: pymongo query with unsanitized request input
def login():
    user = db.users.find_one(request.json)
    if not user:
        return jsonify(error="Invalid"), 401
    return jsonify(status="ok")

# VULNERABLE: $where with f-string
def search_users():
    term = request.args.get('q')
    users = db.users.find({"$where": f"this.name.includes('{term}')"})
    return jsonify(list(users))
