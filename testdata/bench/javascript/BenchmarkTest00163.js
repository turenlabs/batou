// Vulnerable: Open redirect via res.redirect with req.body
const express = require('express');
const router = express.Router();
router.post('/test163', (req, res) => {
    const returnUrl = req.body.returnUrl;
    res.redirect(returnUrl);
});
module.exports = router;
