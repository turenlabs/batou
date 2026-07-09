// Vulnerable: SQL injection via knex.raw
const express = require('express');
const knex = require('./knex');
const router = express.Router();
router.post('/test009', (req, res) => {
    const param = req.body.filter;
    knex.raw("SELECT * FROM orders WHERE status = '" + param + "'")
        .then(results => res.json(results))
        .catch(err => res.status(500).json({ error: 'Query failed' }));
});
module.exports = router;
