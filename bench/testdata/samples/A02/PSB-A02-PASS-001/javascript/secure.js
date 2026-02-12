// PSB-A02-PASS-001: Password storage/registration
// CWE: CWE-916, CWE-328
// Expected: (none - secure)
const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./db");
const app = express();
app.use(express.json());

const SALT_ROUNDS = 12;

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
    return res.status(400).json({ error: "invalid email" });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  const hashed = await bcrypt.hash(password, SALT_ROUNDS);

  await db.query(
    "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)",
    [username, email, hashed]
  );

  res.status(201).json({ username, email });
});

module.exports = app;
