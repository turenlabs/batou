// Vulnerable: SQL injection via string concatenation
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test001', (req, res) => {
    const param = req.query.input;
    const sql = "SELECT * FROM users WHERE id = " + param;
    db.query(sql, (err, results) => { res.json(results); });
});
module.exports = router;
