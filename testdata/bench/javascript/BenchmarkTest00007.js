// Vulnerable: SQL injection via Sequelize raw query
const express = require('express');
const sequelize = require('./sequelize');
const router = express.Router();
router.get('/test007', (req, res) => {
    const param = req.query.username;
    sequelize.query("SELECT * FROM users WHERE username = '" + param + "'")
        .then(results => res.json(results))
        .catch(err => res.status(500).json({ error: 'Query failed' }));
});
module.exports = router;
