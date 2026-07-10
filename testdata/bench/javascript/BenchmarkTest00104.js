// Safe: NoSQL injection prevented via explicit field extraction
const express = require('express');
const router = express.Router();
const Product = require('./models/Product');
router.post('/test104', async (req, res) => {
    const name = String(req.body.name || '');
    const category = String(req.body.category || '');
    const products = await Product.find({ name, category });
    res.json(products);
});
module.exports = router;
