// Vulnerable: SQL injection via req.params in template literal
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/users/:role', (req, res) => {
    const role = req.params.role;
    const sql = `SELECT name, email FROM users WHERE role = '${role}'`;
    db.query(sql, (err, results) => { res.json(results); });
});
module.exports = router;
