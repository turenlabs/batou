// Safe: Redirect prevented via startsWith check
const express = require('express');
const router = express.Router();
router.get('/test172', (req, res) => {
    const savedUrl = req.cookies.lastPage || '/home';
    if (!savedUrl.startsWith('/') || savedUrl.startsWith('//')) {
        return res.redirect('/home');
    }
    res.redirect(savedUrl);
});
module.exports = router;
