// Vulnerable: XSS via res.write with user input
const express = require('express');
const router = express.Router();
router.get('/test027', (req, res) => {
    const query = req.query.q;
    res.write('<html><body>');
    res.write('<p>Search results for: ' + query + '</p>');
    res.write('</body></html>');
    res.end();
});
module.exports = router;
