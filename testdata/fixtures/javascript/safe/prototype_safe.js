// Safe: Prototype pollution prevention patterns
const express = require('express');
const app = express();

app.post('/config', (req, res) => {
  // SAFE: Sanitize input before merge
  const sanitized = sanitize(req.body);
  _.merge(config, sanitized);

  // SAFE: Merge with no user input
  const defaults = { timeout: 5000, retries: 3 };
  _.merge(config, defaults);

  // SAFE: Using Object.create(null) to prevent prototype access
  const safeObj = Object.create(null);
  Object.assign(safeObj, cleanInput(req.body));

  // SAFE: Defensive proto check
  if (key === "__proto__") {
    return res.status(400).json({ error: "invalid key" });
  }

  res.json({ status: 'ok' });
});
