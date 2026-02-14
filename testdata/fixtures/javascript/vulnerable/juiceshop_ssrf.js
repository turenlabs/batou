// Juice Shop SSRF
// Expected: GTSS-SSRF-001
// CWE-918, OWASP A10
const express = require('express');
const axios = require('axios');
const http = require('http');
const app = express();

app.get('/api/proxy', (req, res) => {
  const targetUrl = req.query.url;

  // VULNERABLE: Juice Shop SSRF - fetching user-controlled URL
  axios.get(targetUrl).then(response => {
    res.json(response.data);
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
});

app.post('/api/fetch', (req, res) => {
  const url = req.body.url;

  // VULNERABLE: SSRF via http.get with user-controlled URL
  http.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  });
});
