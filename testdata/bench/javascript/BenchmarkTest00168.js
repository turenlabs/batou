// Safe: Redirect prevented via URL origin check
const express = require('express');
const router = express.Router();
router.get('/test168', (req, res) => {
    const target = req.query.target;
    try {
        const parsed = new URL(target, 'https://example.com');
        if (parsed.origin !== 'https://example.com') {
            return res.redirect('/');
        }
        res.redirect(parsed.pathname + parsed.search);
    } catch (e) {
        res.redirect('/');
    }
});
module.exports = router;
