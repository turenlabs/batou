// Vulnerable: XSS via header value reflected in body
const express = require('express');
const router = express.Router();
router.get('/test037', (req, res) => {
    const referer = req.headers.referer;
    res.send('<p>Referred from: ' + referer + '</p>');
});
module.exports = router;
