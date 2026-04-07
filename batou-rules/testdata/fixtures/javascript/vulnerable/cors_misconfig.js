// Vulnerable: CORS misconfiguration patterns
const express = require('express');
const cors = require('cors');
const app = express();

// VULNERABLE: Wildcard origin with credentials
app.use(cors({
  origin: '*',
  credentials: true
}));

// VULNERABLE: Reflected origin without validation
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});
