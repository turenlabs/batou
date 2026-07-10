// Vulnerable: Stored XSS via database retrieval sent directly
const express = require('express');
const db = require('./db');
const router = express.Router();
router.post('/test033', (req, res) => {
    const bio = req.body.bio;
    res.send('<div class="bio">' + bio + '</div>');
});
module.exports = router;
