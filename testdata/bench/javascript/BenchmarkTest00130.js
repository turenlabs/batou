// Safe: Expression evaluation via safe math parser
const express = require('express');
const router = express.Router();
router.post('/test130', (req, res) => {
    const expression = req.body.expr;
    if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
        return res.status(400).json({ error: 'Invalid expression' });
    }
    try {
        const fn = new Function('return (' + expression + ')');
        res.json({ result: fn() });
    } catch (e) {
        res.status(400).json({ error: 'Evaluation failed' });
    }
});
module.exports = router;
