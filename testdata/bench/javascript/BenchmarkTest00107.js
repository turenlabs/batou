// Vulnerable: NoSQL injection via MongoDB aggregate with user data
const express = require('express');
const router = express.Router();
const Order = require('./models/Order');
router.post('/test107', async (req, res) => {
    const match = req.body.match;
    const results = await Order.aggregate([{ $match: match }]);
    res.json(results);
});
module.exports = router;
