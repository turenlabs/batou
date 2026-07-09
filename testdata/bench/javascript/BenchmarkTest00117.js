// Vulnerable: NoSQL injection via findOneAndUpdate
const express = require('express');
const router = express.Router();
const Cart = require('./models/Cart');
router.post('/test117', async (req, res) => {
    const query = req.body.query;
    const update = req.body.update;
    const result = await Cart.findOneAndUpdate(query, update, { new: true });
    res.json(result);
});
module.exports = router;
