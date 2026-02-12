// PSB-A03-SQL-001: User search endpoint
// CWE: CWE-89
// Expected: GTSS-INJ-001, GTSS-INJ-002
const express = require("express");
const db = require("./db");
const app = express();

app.get("/api/users/search", async (req, res) => {
  const q = req.query.q;
  if (!q) {
    return res.status(400).json({ error: "query parameter 'q' is required" });
  }

  try {
    const query = `SELECT id, name, email FROM users WHERE name LIKE '%${q}%'`;
    const result = await db.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "database error" });
  }
});

module.exports = app;
