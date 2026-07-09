// Vulnerable: SQL injection via template literal
const express = require('express');
const db = require('./db');
const router = express.Router();
router.post('/test003', (req, res) => {
    const name = req.body.name;
    const sql = `SELECT * FROM products WHERE name = '${name}'`;
    db.query(sql, (err, results) => { res.json(results); });
});
module.exports = router;
