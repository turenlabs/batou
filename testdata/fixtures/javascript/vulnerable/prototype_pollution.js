// Vulnerable: Prototype pollution via deep merge with user input
const express = require('express');
const _ = require('lodash');
const app = express();

app.post('/config', (req, res) => {
  const userConfig = req.body;

  // VULNERABLE: Deep merge user input into config object
  _.merge(globalConfig, req.body);

  // VULNERABLE: defaultsDeep with user input
  _.defaultsDeep(settings, req.body);

  // VULNERABLE: Object.assign with user input
  Object.assign(user, req.body);

  // VULNERABLE: Spread with user input into model
  const updated = {...user, ...req.body};

  // VULNERABLE: Direct __proto__ access
  obj["__proto__"] = payload;

  // VULNERABLE: constructor.prototype
  obj.constructor.prototype.isAdmin = true;

  res.json({ status: 'updated' });
});
