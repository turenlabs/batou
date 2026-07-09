// Safe: SQL injection prevented via parameterized query
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test002', (req, res) => {
    const param = req.query.input;
    db.query("SELECT * FROM users WHERE id = ?", [param], (err, results) => { res.json(results); });
});
module.exports = router;
