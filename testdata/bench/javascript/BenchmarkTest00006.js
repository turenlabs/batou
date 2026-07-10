// Safe: SQL injection prevented via parseInt validation
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test006', (req, res) => {
    const param = req.query.id;
    const safeId = parseInt(param, 10);
    if (isNaN(safeId)) { return res.status(400).json({ error: 'Invalid ID' }); }
    const sql = "SELECT * FROM users WHERE id = " + safeId;
    db.query(sql, (err, results) => { res.json(results); });
});
module.exports = router;
