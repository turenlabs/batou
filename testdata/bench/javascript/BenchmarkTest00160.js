// Safe: SSTI prevented via fixed format mapping
const express = require('express');
const router = express.Router();
const FORMATS = {
    'html': (data) => '<h1>' + data.title + '</h1><p>' + data.date + '</p>',
    'text': (data) => data.title + ' - ' + data.date,
};
router.get('/report/:format', (req, res) => {
    const format = req.params.format;
    const renderer = FORMATS[format];
    if (!renderer) return res.status(400).send('Unknown format');
    res.send(renderer({ title: 'Report', date: new Date().toISOString() }));
});
module.exports = router;
