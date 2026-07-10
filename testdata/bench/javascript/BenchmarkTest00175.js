// Vulnerable: Open redirect via referer header
const express = require('express');
const router = express.Router();
router.get('/test175', (req, res) => {
    const back = req.headers.referer;
    res.redirect(back);
});
module.exports = router;
