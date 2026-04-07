// Safe: Proper CORS configuration patterns
const express = require('express');
const cors = require('cors');
const app = express();

// SAFE: Specific origin with credentials
app.use(cors({
  origin: 'https://myapp.example.com',
  credentials: true
}));

// SAFE: Origin validation with allowlist
const allowedOrigins = ['https://myapp.com', 'https://admin.myapp.com'];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Credentials", "true");
  }
  next();
});
