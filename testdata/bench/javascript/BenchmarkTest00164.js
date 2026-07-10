// Safe: Redirect prevented via allowlisted domains
const express = require('express');
const router = express.Router();
const ALLOWED_DOMAINS = ['example.com', 'app.example.com'];
router.post('/test164', (req, res) => {
    const returnUrl = req.body.returnUrl;
    try {
        const parsed = new URL(returnUrl);
        if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
            return res.redirect('/');
        }
        res.redirect(returnUrl);
    } catch (e) {
        res.redirect('/');
    }
});
module.exports = router;
