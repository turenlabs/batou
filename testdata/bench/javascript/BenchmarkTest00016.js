// Safe: SQL injection prevented via Number coercion
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test016', (req, res) => {
    const raw = req.query.id;
    const userId = Number(raw);
    if (!Number.isFinite(userId)) return res.status(400).send('Invalid ID');
    db.query("DELETE FROM sessions WHERE id = ?", [userId], (err) => {
        if (err) return res.status(500).send('Error');
        res.send('Sessions cleared');
    });
});
module.exports = router;
