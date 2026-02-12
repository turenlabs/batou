// PSB-A08-DESER-001: User data deserialization
// CWE: CWE-502
// Expected: GTSS-INJ-010
const express = require("express");
const serialize = require("node-serialize");
const app = express();
app.use(express.json());

app.post("/api/preferences/import", (req, res) => {
  const { preferences, user_id } = req.body;
  if (!preferences) {
    return res.status(400).json({ error: "preferences data is required" });
  }

  try {
    const prefs = serialize.unserialize(preferences);
    // Apply preferences to user account
    // db.query("UPDATE users SET prefs = $1 WHERE id = $2", [JSON.stringify(prefs), user_id]);

    res.json({ status: "imported", preferences: prefs });
  } catch (err) {
    res.status(400).json({ error: "invalid preferences data" });
  }
});

module.exports = app;
