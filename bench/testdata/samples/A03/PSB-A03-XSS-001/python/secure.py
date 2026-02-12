# PSB-A03-XSS-001: Comment display
# CWE: CWE-79
# Expected: (none - secure)
from flask import Flask, g
from markupsafe import escape
import sqlite3

app = Flask(__name__)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("app.db")
        g.db.row_factory = sqlite3.Row
    return g.db

@app.route("/posts/<int:post_id>/comments")
def show_comments(post_id):
    db = get_db()
    comments = db.execute(
        "SELECT author, text, created_at FROM comments WHERE post_id = ? ORDER BY created_at",
        (post_id,),
    ).fetchall()

    html = "<html><body><h1>Comments</h1>"
    for c in comments:
        safe_author = escape(c["author"])
        safe_text = escape(c["text"]).replace("\n", "<br>")
        html += f'<div class="comment">'
        html += f"<strong>{safe_author}</strong>"
        html += f'<span>{c["created_at"]}</span>'
        html += f"<p>{safe_text}</p>"
        html += "</div>"
    html += "</body></html>"
    return html

if __name__ == "__main__":
    app.run()
