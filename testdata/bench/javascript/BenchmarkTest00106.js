// Safe: NoSQL injection prevented via mongo-sanitize
const express = require('express');
const sanitize = require('mongo-sanitize');
const router = express.Router();
const User = require('./models/User');
router.get('/test106', async (req, res) => {
    const pattern = sanitize(req.query.pattern);
    const users = await User.find({ email: { $regex: String(pattern) } });
    res.json(users);
});
module.exports = router;
