// Safe: SQL injection prevented via ORM (Knex query builder)
const express = require('express');
const knex = require('./knex');
const router = express.Router();
router.get('/test004', (req, res) => {
    const param = req.query.input;
    knex('users').where('id', param).first()
        .then(user => res.json(user))
        .catch(err => res.status(500).json({ error: 'Database error' }));
});
module.exports = router;
