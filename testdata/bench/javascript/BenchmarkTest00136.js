// Safe: Sandboxed computation via pure function lookup
const express = require('express');
const router = express.Router();
const FORMULAS = {
    'circle_area': (r) => Math.PI * r * r,
    'rect_area': (w, h) => w * h,
    'triangle_area': (b, h) => 0.5 * b * h
};
router.post('/test136', (req, res) => {
    const formula = req.body.formula;
    const args = (req.body.args || []).map(Number);
    const fn = FORMULAS[formula];
    if (!fn) return res.status(400).json({ error: 'Unknown formula' });
    res.json({ result: fn(...args) });
});
module.exports = router;
