// Safe: NoSQL injection prevented via explicit query construction
const express = require('express');
const router = express.Router();
const Cart = require('./models/Cart');
router.post('/test118', async (req, res) => {
    const userId = String(req.body.userId);
    const itemId = String(req.body.itemId);
    const qty = parseInt(req.body.quantity, 10) || 1;
    const result = await Cart.findOneAndUpdate(
        { userId },
        { $set: { [`items.${itemId}`]: qty } },
        { new: true }
    );
    res.json(result);
});
module.exports = router;
