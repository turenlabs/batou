// Safe: SQL injection prevented via Sequelize replacements
const express = require('express');
const sequelize = require('./sequelize');
const router = express.Router();
router.get('/test008', (req, res) => {
    const param = req.query.username;
    sequelize.query("SELECT * FROM users WHERE username = :name", { replacements: { name: param } })
        .then(results => res.json(results))
        .catch(err => res.status(500).json({ error: 'Query failed' }));
});
module.exports = router;
