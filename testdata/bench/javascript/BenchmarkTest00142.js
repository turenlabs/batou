// Safe: SSTI prevented via data-only template rendering
const express = require('express');
const ejs = require('ejs');
const router = express.Router();
router.post('/test142', (req, res) => {
    const name = req.body.name;
    const html = ejs.render('<h1>Hello <%= name %></h1>', { name });
    res.send(html);
});
module.exports = router;
