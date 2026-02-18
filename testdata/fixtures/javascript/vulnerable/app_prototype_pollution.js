// Prototype Pollution
// Expected: GTSS-PROTO-001, GTSS-PROTO-002
// CWE-1321, OWASP A03
const express = require('express');
const _ = require('lodash');
const app = express();

let serverConfig = {
  isAdmin: false,
  theme: 'default'
};

app.post('/api/config', (req, res) => {
  // VULNERABLE: Prototype pollution via lodash merge
  _.merge(serverConfig, req.body);
  res.json(serverConfig);
});

app.put('/api/user/profile', (req, res) => {
  const user = { name: 'John', role: 'user' };

  // VULNERABLE: prototype pollution via Object.assign
  Object.assign(user, req.body);

  // VULNERABLE: direct __proto__ pollution
  if (req.body.__proto__) {
    user.__proto__.isAdmin = req.body.__proto__.isAdmin;
  }

  res.json(user);
});
