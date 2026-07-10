// Safe: XSS prevented via encodeURIComponent for URL context
const express = require('express');
const router = express.Router();
router.get('/test036', (req, res) => {
    const term = req.query.term;
    const safeTerm = encodeURIComponent(term);
    res.send('<a href="/search?q=' + safeTerm + '">Search again</a>');
});
module.exports = router;
