// PSB-A01-TRAV-001: File download endpoint
// CWE: CWE-22, CWE-23
// Expected: (none - secure)
const express = require("express");
const path = require("path");
const app = express();

const UPLOAD_DIR = "/var/app/uploads";

app.get("/api/download", (req, res) => {
  const filename = req.query.filename;
  if (!filename) {
    return res.status(400).json({ error: "filename is required" });
  }

  const resolved = path.resolve(UPLOAD_DIR, filename);
  if (!resolved.startsWith(path.resolve(UPLOAD_DIR))) {
    return res.status(403).json({ error: "access denied" });
  }

  res.sendFile(resolved);
});

module.exports = app;
