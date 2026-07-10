// Vulnerable: NoSQL injection via direct req.body as query object
const express = require('express');
const router = express.Router();
const Product = require('./models/Product');
router.post('/test103', async (req, res) => {
    const query = req.body;
    const products = await Product.find(query);
    res.json(products);
});
module.exports = router;
