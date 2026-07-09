// Vulnerable: SQL injection via multi-step variable assignment
const express = require('express');
const db = require('./db');
const router = express.Router();
router.get('/test015', (req, res) => {
    const raw = req.query.id;
    const userId = raw;
    const condition = "id = " + userId;
    const query = "DELETE FROM sessions WHERE " + condition;
    db.query(query, (err) => {
        if (err) return res.status(500).send('Error');
        res.send('Sessions cleared');
    });
});
module.exports = router;
