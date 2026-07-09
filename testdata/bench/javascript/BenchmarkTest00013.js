// Vulnerable: SQL injection via execute with string interpolation
const express = require('express');
const db = require('./db');
const router = express.Router();
router.post('/test013', (req, res) => {
    const category = req.body.category;
    const sort = req.body.sort;
    db.execute(`SELECT * FROM products WHERE category = '${category}' ORDER BY ${sort}`)
        .then(results => res.json(results));
});
module.exports = router;
