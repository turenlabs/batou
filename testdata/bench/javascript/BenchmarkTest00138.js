// Safe: Deserialization via try/catch JSON.parse with type check
const express = require('express');
const router = express.Router();
router.post('/test138', (req, res) => {
    const rawInput = req.body.payload;
    if (typeof rawInput !== 'string') {
        return res.status(400).json({ error: 'Expected string' });
    }
    try {
        const parsed = JSON.parse(rawInput);
        if (typeof parsed !== 'object' || parsed === null) {
            return res.status(400).json({ error: 'Expected object' });
        }
        res.json({ result: parsed });
    } catch (e) {
        res.status(400).json({ error: 'Invalid JSON' });
    }
});
module.exports = router;
