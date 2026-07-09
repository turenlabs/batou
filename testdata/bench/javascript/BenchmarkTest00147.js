// Vulnerable: SSTI via res.render with user-controlled view name
const express = require('express');
const router = express.Router();
router.get('/test147', (req, res) => {
    const page = req.query.page;
    res.render(page, { title: 'Page' });
});
module.exports = router;
