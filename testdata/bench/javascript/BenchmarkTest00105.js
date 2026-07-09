// Vulnerable: NoSQL injection via $regex with user input
const express = require('express');
const router = express.Router();
const User = require('./models/User');
router.get('/test105', async (req, res) => {
    const pattern = req.query.pattern;
    const users = await User.find({ email: { $regex: pattern } });
    res.json(users);
});
module.exports = router;
