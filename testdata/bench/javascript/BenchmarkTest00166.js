// Safe: Redirect prevented via path-only redirect
const express = require('express');
const router = express.Router();
const VALID_PATHS = ['/dashboard', '/profile', '/settings', '/home'];
router.get('/test166', (req, res) => {
    const next = req.query.next;
    if (!VALID_PATHS.includes(next)) {
        return res.redirect('/home');
    }
    res.redirect(next);
});
module.exports = router;
