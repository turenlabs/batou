// JWT - Fixed with algorithm restriction
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.get('/rest/user/whoami', (req, res) => {
  const token = req.headers.authorization;
  const secret = process.env.JWT_SECRET;

  // SAFE: Specifying algorithms explicitly prevents "none" algorithm attack
  const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
  res.json({ user: decoded });
});
