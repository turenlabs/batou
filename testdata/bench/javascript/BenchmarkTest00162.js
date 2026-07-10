// Safe: Redirect prevented via relative path only
const express = require('express');
const router = express.Router();
router.get('/test162', (req, res) => {
    const path = req.query.path;
    if (path.startsWith('http') || path.startsWith('//')) {
        return res.status(400).send('External redirects not allowed');
    }
    res.redirect('/' + path.replace(/^\/+/, ''));
});
module.exports = router;
