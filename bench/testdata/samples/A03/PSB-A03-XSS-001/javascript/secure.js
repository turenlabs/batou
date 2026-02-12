// PSB-A03-XSS-001: Comment display
// CWE: CWE-79
// Expected: (none - secure)
const express = require("express");
const db = require("./db");
const app = express();

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

app.get("/posts/:id/comments", async (req, res) => {
  const postId = req.params.id;
  const comments = await db.query(
    "SELECT author, text, created_at FROM comments WHERE post_id = $1 ORDER BY created_at",
    [postId]
  );

  let html = "<html><body><h1>Comments</h1>";
  for (const c of comments.rows) {
    const safeAuthor = escapeHtml(c.author);
    const safeText = escapeHtml(c.text).replace(/\n/g, "<br>");
    html += `<div class="comment">`;
    html += `<strong>${safeAuthor}</strong>`;
    html += `<span>${c.created_at}</span>`;
    html += `<p>${safeText}</p>`;
    html += `</div>`;
  }
  html += "</body></html>";
  res.send(html);
});

module.exports = app;
