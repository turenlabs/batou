// Safe: Redirect prevented via regex for same-origin
const express = require('express');
const router = express.Router();
router.get('/test174', (req, res) => {
    const callbackUrl = req.query.callback;
    if (!/^\/[a-zA-Z0-9/_-]+$/.test(callbackUrl)) {
        return res.redirect('/');
    }
    res.redirect(callbackUrl);
});
module.exports = router;
