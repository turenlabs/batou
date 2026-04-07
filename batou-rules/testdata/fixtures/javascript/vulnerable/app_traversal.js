// Directory Traversal
// Expected: GTSS-TRV-001, GTSS-JSTS-011
// CWE-22, OWASP A01
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

app.get('/rest/ftp/:file', (req, res) => {
  const filename = req.params.file;

  // VULNERABLE: Directory traversal - path.join doesn't prevent ../
  const filePath = path.join(__dirname, 'ftp', filename);
  res.sendFile(filePath);
});

app.get('/api/download', (req, res) => {
  const file = req.query.file;

  // VULNERABLE: Directory traversal via string concatenation
  const fullPath = './uploads/' + file;
  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.status(404).send('Not found');
    } else {
      res.send(data);
    }
  });
});
