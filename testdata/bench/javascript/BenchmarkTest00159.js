// Vulnerable: SSTI via ejs.render with params
const express = require('express');
const ejs = require('ejs');
const router = express.Router();
router.get('/report/:format', (req, res) => {
    const format = req.params.format;
    const tplStr = '<%= ' + format + ' %>';
    const html = ejs.render(tplStr, { title: 'Report', date: new Date() });
    res.send(html);
});
module.exports = router;
