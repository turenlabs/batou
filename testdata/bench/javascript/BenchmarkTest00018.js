// Safe: SQL injection prevented via whitelist for role
const express = require('express');
const db = require('./db');
const router = express.Router();
const VALID_ROLES = ['admin', 'user', 'editor', 'viewer'];
router.get('/users/:role', (req, res) => {
    const role = req.params.role;
    if (!VALID_ROLES.includes(role)) return res.status(400).send('Invalid role');
    db.query("SELECT name, email FROM users WHERE role = ?", [role], (err, results) => {
        res.json(results);
    });
});
module.exports = router;
