// Safe: Deserialization via allowlisted transform functions
const express = require('express');
const router = express.Router();
const TRANSFORMS = {
    'sum': (data) => data.items.reduce((a, b) => a + b, 0),
    'count': (data) => data.items.length,
    'max': (data) => Math.max(...data.items)
};
router.post('/test126', (req, res) => {
    const name = req.body.transform;
    const fn = TRANSFORMS[name];
    if (!fn) return res.status(400).json({ error: 'Unknown transform' });
    const result = fn({ items: [1, 2, 3] });
    res.json({ result });
});
module.exports = router;
