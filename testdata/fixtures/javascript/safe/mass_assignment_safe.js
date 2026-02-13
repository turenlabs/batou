// Safe: Mass assignment prevention patterns
const express = require('express');
const User = require('./models/User');
const app = express();

app.post('/users', async (req, res) => {
  // SAFE: Explicit field picking
  const { name, email } = req.body;
  const user = new User({ name, email });

  // SAFE: Using _.pick to whitelist fields
  const allowed = _.pick(req.body, ['name', 'email']);
  Object.assign(user, allowed);

  // SAFE: Using allowedFields list
  const allowedFields = ['name', 'email', 'bio'];
  const filtered = {};
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) {
      filtered[field] = req.body[field];
    }
  }

  await user.save();
  res.json(user);
});
