// Juice Shop SQL Injection via Sequelize
// Expected: GTSS-INJ-001 (SQL Injection)
// CWE-89, OWASP A03
const express = require('express');
const sequelize = require('./models').sequelize;
const app = express();

app.post('/rest/user/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // VULNERABLE: Juice Shop SQL injection via raw query with string concatenation
  sequelize.query(
    "SELECT * FROM Users WHERE email = '" + email + "' AND password = '" + password + "'",
    { type: sequelize.QueryTypes.SELECT }
  ).then(users => {
    if (users.length > 0) {
      res.json({ authentication: { token: 'fake-jwt' } });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

app.get('/rest/products/search', (req, res) => {
  const query = req.query.q;

  // VULNERABLE: Juice Shop search SQL injection
  sequelize.query(
    "SELECT * FROM Products WHERE name LIKE '%" + query + "%' OR description LIKE '%" + query + "%'",
    { type: sequelize.QueryTypes.SELECT }
  ).then(products => {
    res.json(products);
  });
});
