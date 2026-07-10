// Safe: NoSQL injection prevented via schema validation
const express = require('express');
const router = express.Router();
const Order = require('./models/Order');
router.post('/test108', async (req, res) => {
    const status = String(req.body.status || 'pending');
    const minTotal = Number(req.body.minTotal) || 0;
    const results = await Order.aggregate([
        { $match: { status, total: { $gte: minTotal } } }
    ]);
    res.json(results);
});
module.exports = router;
