// Safe: SSTI prevented via allowlisted view names
const express = require('express');
const router = express.Router();
const ALLOWED_PAGES = ['home', 'about', 'contact', 'faq'];
router.get('/test148', (req, res) => {
    const page = req.query.page;
    if (!ALLOWED_PAGES.includes(page)) {
        return res.status(404).send('Page not found');
    }
    res.render(page, { title: page });
});
module.exports = router;
