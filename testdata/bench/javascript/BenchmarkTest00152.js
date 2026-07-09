// Safe: SSTI prevented via simple string replacement
const express = require('express');
const router = express.Router();
router.post('/test152', (req, res) => {
    const name = req.body.name;
    const template = '<h1>Hello {{name}}</h1>';
    const result = template.replace('{{name}}', name.replace(/[<>&"]/g, c => ({
        '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;'
    }[c])));
    res.send(result);
});
module.exports = router;
