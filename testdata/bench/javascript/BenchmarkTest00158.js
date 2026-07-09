// Safe: SSTI prevented by using Mustache-style with no logic
const express = require('express');
const Handlebars = require('handlebars');
const router = express.Router();
const template = Handlebars.compile('{{data}}');
router.get('/test158', (req, res) => {
    const data = req.query.data || 'default';
    res.send(template({ data: String(data) }));
});
module.exports = router;
