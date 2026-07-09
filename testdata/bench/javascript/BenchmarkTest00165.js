// Vulnerable: Open redirect via header Location set
const express = require('express');
const router = express.Router();
router.get('/test165', (req, res) => {
    const next = req.query.next;
    res.setHeader('Location', next);
    res.status(302).end();
});
module.exports = router;
