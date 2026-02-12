// PSB-A02-PASS-001: Password storage/registration
// CWE: CWE-916, CWE-328
// Expected: GTSS-CRYPTO-001, GTSS-CRYPTO-002
const express = require("express");
const crypto = require("crypto");
const db = require("./db");
const app = express();
app.use(express.json());

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
    return res.status(400).json({ error: "invalid email" });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  const hashed = crypto.createHash("md5").update(password).digest("hex");

  await db.query(
    "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
    [username, email, hashed]
  );

  res.status(201).json({ username, email });
});

module.exports = app;
