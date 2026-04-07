// SQL Injection - Fixed with parameterized queries
const express = require('express');
const { QueryTypes } = require('sequelize');
const sequelize = require('./models').sequelize;
const app = express();

app.post('/rest/user/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // SAFE: Parameterized query with replacements
  sequelize.query(
    "SELECT * FROM Users WHERE email = ? AND password = ?",
    { replacements: [email, password], type: QueryTypes.SELECT }
  ).then(users => {
    if (users.length > 0) {
      res.json({ authentication: { token: 'fake-jwt' } });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});
