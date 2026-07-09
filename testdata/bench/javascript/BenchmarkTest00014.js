// Safe: SQL injection prevented via prepared statement with execute
const express = require('express');
const db = require('./db');
const router = express.Router();
const ALLOWED_SORTS = ['name', 'price', 'created_at'];
router.post('/test014', (req, res) => {
    const category = req.body.category;
    const sort = ALLOWED_SORTS.includes(req.body.sort) ? req.body.sort : 'name';
    db.execute('SELECT * FROM products WHERE category = ? ORDER BY ' + sort, [category])
        .then(results => res.json(results));
});
module.exports = router;
