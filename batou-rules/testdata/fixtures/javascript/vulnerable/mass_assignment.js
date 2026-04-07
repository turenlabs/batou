// Vulnerable: Mass assignment via direct user input to models
const express = require('express');
const User = require('./models/User');
const app = express();

app.post('/users', async (req, res) => {
  // VULNERABLE: Object.assign model with raw user input
  Object.assign(user, req.body);

  // VULNERABLE: Spread into model
  const updated = {...user, ...req.body};

  // VULNERABLE: ORM update with raw body
  await User.findOneAndUpdate(req.body);

  // VULNERABLE: Model constructor with raw input
  const newUser = new User(req.body);

  res.json(newUser);
});
