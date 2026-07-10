// Safe: NoSQL injection prevented via Mongoose query builder
const express = require('express');
const router = express.Router();
const User = require('./models/User');
router.get('/test102', async (req, res) => {
    const search = req.query.search;
    const users = await User.find({ name: { $eq: String(search) } });
    res.json(users);
});
module.exports = router;
