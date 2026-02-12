// PSB-A03-XSS-001: Comment display
// CWE: CWE-79
// Expected: GTSS-XSS-001, GTSS-XSS-002
const express = require("express");
const db = require("./db");
const app = express();

app.get("/posts/:id/comments", async (req, res) => {
  const postId = req.params.id;
  const comments = await db.query(
    "SELECT author, text, created_at FROM comments WHERE post_id = $1 ORDER BY created_at",
    [postId]
  );

  let html = "<html><body><h1>Comments</h1>";
  for (const c of comments.rows) {
    html += `<div class="comment">`;
    html += `<strong>${c.author}</strong>`;
    html += `<span>${c.created_at}</span>`;
    html += `<p>${c.text.replace(/\n/g, "<br>")}</p>`;
    html += `</div>`;
  }
  html += "</body></html>";
  res.send(html);
});

module.exports = app;
