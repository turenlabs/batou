// Safe: XSS prevented via validator.escape
const express = require('express');
const validator = require('validator');
const router = express.Router();
router.get('/test028', (req, res) => {
    const query = req.query.q;
    const safeQuery = validator.escape(query);
    res.send('<p>Search results for: ' + safeQuery + '</p>');
});
module.exports = router;
