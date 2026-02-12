// PSB-A08-DESER-001: User data deserialization
// CWE: CWE-502
// Expected: (none - secure)
const express = require("express");
const app = express();
app.use(express.json());

const ALLOWED_KEYS = new Set(["theme", "language", "timezone", "notifications", "font_size"]);

app.post("/api/preferences/import", (req, res) => {
  const { preferences, user_id } = req.body;
  if (!preferences) {
    return res.status(400).json({ error: "preferences data is required" });
  }

  let parsed;
  try {
    parsed = typeof preferences === "string" ? JSON.parse(preferences) : preferences;
  } catch (err) {
    return res.status(400).json({ error: "invalid JSON preferences" });
  }

  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    return res.status(400).json({ error: "preferences must be an object" });
  }

  const safePrefs = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (ALLOWED_KEYS.has(key)) {
      safePrefs[key] = value;
    }
  }

  // db.query("UPDATE users SET prefs = $1 WHERE id = $2", [JSON.stringify(safePrefs), user_id]);
  res.json({ status: "imported", preferences: safePrefs });
});

module.exports = app;
