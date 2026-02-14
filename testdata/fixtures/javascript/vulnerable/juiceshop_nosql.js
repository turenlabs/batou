// Juice Shop NoSQL Injection
// Expected: GTSS-NOSQL-001, GTSS-NOSQL-002, GTSS-INJ-007
// CWE-943, OWASP A03
const express = require('express');
const User = require('./models/user');
const app = express();

app.post('/rest/user/login', (req, res) => {
  // VULNERABLE: Juice Shop NoSQL injection - passing user input directly to query
  User.find({
    email: req.body.email,
    password: req.body.password
  }).then(user => {
    res.json(user);
  });
});

app.get('/api/users', (req, res) => {
  const filter = req.query.filter;

  // VULNERABLE: NoSQL operator injection via $where
  User.find({ $where: "this.name === '" + filter + "'" })
    .then(users => res.json(users));
});

app.post('/api/reviews', (req, res) => {
  // VULNERABLE: NoSQL injection with user-controlled operators
  const query = { rating: { $gt: req.body.minRating } };
  Review.find(query).then(reviews => res.json(reviews));
});
