// Safe: SSTI prevented by using res.json (no template)
const express = require('express');
const router = express.Router();
router.post('/test154', (req, res) => {
    const data = req.body;
    res.json({ greeting: 'Hello ' + String(data.name || 'World') });
});
module.exports = router;
