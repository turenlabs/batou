// Safe: Deserialization via safe JSON.parse only
const express = require('express');
const router = express.Router();
router.post('/test122', (req, res) => {
    const data = req.body.payload;
    try {
        const parsed = JSON.parse(data);
        res.json({ result: parsed });
    } catch (e) {
        res.status(400).json({ error: 'Invalid JSON' });
    }
});
module.exports = router;
