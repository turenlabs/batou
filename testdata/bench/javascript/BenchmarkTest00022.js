// Safe: XSS prevented via HTML escaping
const express = require('express');
const escapeHtml = require('escape-html');
const router = express.Router();
router.get('/test022', (req, res) => {
    const name = req.query.name;
    res.send('<h1>Hello ' + escapeHtml(name) + '</h1>');
});
module.exports = router;
