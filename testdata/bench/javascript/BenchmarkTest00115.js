// Vulnerable: NoSQL injection via $where with template literal
const express = require('express');
const router = express.Router();
const Item = require('./models/Item');
router.get('/test115', async (req, res) => {
    const minPrice = req.query.min;
    const items = await Item.find({ $where: `this.price >= ${minPrice}` });
    res.json(items);
});
module.exports = router;
