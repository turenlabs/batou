// PSB-A01-TRAV-001: File download endpoint
// CWE: CWE-22, CWE-23
// Expected: GTSS-TRAV-001, GTSS-TRAV-003
const express = require("express");
const path = require("path");
const app = express();

const UPLOAD_DIR = "/var/app/uploads";

app.get("/api/download", (req, res) => {
  const filename = req.query.filename;
  if (!filename) {
    return res.status(400).json({ error: "filename is required" });
  }

  const filePath = path.join(UPLOAD_DIR, filename);
  res.sendFile(filePath);
});

module.exports = app;
