// Insecure Deserialization
// Expected: GTSS-GEN-002 (Unsafe Deserialization)
// CWE-502, OWASP A08
const express = require('express');
const serialize = require('node-serialize');
const app = express();

app.post('/api/basket/coupon', (req, res) => {
  const couponData = req.body.coupon;

  // VULNERABLE: Insecure deserialization via node-serialize
  const coupon = serialize.unserialize(couponData);

  if (coupon && coupon.valid) {
    res.json({ discount: coupon.discount });
  } else {
    res.status(400).json({ error: 'Invalid coupon' });
  }
});

app.post('/api/import', (req, res) => {
  const data = Buffer.from(req.body.data, 'base64').toString();

  // VULNERABLE: eval-based deserialization
  const obj = eval('(' + data + ')');
  res.json(obj);
});
