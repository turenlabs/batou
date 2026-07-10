// Vulnerable: Open redirect via cookie value
const express = require('express');
const router = express.Router();
router.get('/test171', (req, res) => {
    const savedUrl = req.cookies.lastPage;
    res.redirect(savedUrl);
});
module.exports = router;
