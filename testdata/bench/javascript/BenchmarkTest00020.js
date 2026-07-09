// Safe: SQL injection prevented via parameterized query for auth
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test020', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    db.query("SELECT * FROM api_keys WHERE key_value = ?", [apiKey], (err, results) => {
        res.json(results);
    });
});
module.exports = router;
