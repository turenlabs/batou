import express from 'express';

const app = express();

app.get('/api/data', (req, res) => {
  // SAFE: encode value before setting header
  const requestId = encodeURIComponent(req.query.requestId || '');
  res.setHeader('X-Request-Id', requestId);
  res.json({ ok: true });
});
