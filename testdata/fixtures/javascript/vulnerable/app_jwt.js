// JWT None Algorithm Attack
// Expected: GTSS-JSTS-006 (JWT Verify No Algorithm)
// CWE-347, OWASP A02
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// VULNERABLE: JWT none algorithm - no algorithm restriction
const SECRET = 'juice-shop-secret';

app.get('/rest/user/whoami', (req, res) => {
  const token = req.headers.authorization;

  // VULNERABLE: jwt.verify without specifying algorithms allows "none" algorithm
  const decoded = jwt.verify(token, SECRET);
  res.json({ user: decoded });
});

app.post('/rest/user/login', (req, res) => {
  // VULNERABLE: jwt.sign with weak secret
  const token = jwt.sign(
    { id: 1, email: req.body.email, role: 'customer' },
    SECRET
  );
  res.json({ token });
});
