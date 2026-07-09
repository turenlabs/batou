// Safe: SSTI prevented via ejs.renderFile with fixed template
const express = require('express');
const ejs = require('ejs');
const path = require('path');
const router = express.Router();
router.post('/test150', (req, res) => {
    const items = (req.body.items || []).map(String);
    ejs.renderFile(path.join(__dirname, 'views', 'list.ejs'), { items }, (err, html) => {
        if (err) return res.status(500).send('Render error');
        res.send(html);
    });
});
module.exports = router;
