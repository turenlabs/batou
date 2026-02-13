import express from 'express';

const app = express();

app.get('/api/data', (req, res) => {
  // VULNERABLE: setting header from req.query without CRLF sanitization
  res.setHeader('X-Request-Id', req.query.requestId);
  res.set('X-Custom-Header', req.query.custom);
  res.header('X-User-Agent', req.headers['x-forwarded-for']);
  res.json({ ok: true });
});
