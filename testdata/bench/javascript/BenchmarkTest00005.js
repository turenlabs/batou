// Vulnerable: SQL injection via variable indirection
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test005', (req, res) => {
    const userInput = req.query.search;
    const term = userInput;
    const filter = "name LIKE '%" + term + "%'";
    const sql = "SELECT * FROM items WHERE " + filter;
    db.query(sql, (err, results) => { res.json(results); });
});
module.exports = router;
