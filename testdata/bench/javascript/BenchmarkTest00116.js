// Safe: NoSQL injection prevented via numeric conversion
const express = require('express');
const router = express.Router();
const Item = require('./models/Item');
router.get('/test116', async (req, res) => {
    const minPrice = Number(req.query.min) || 0;
    const items = await Item.find({ price: { $gte: minPrice } });
    res.json(items);
});
module.exports = router;
