// Vulnerable: SQL injection via header value in query
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test019', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const sql = "SELECT * FROM api_keys WHERE key_value = '" + apiKey + "'";
    db.query(sql, (err, results) => { res.json(results); });
});
module.exports = router;
