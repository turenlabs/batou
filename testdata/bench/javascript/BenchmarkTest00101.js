// Vulnerable: NoSQL injection via MongoDB $where with user input
const express = require('express');
const router = express.Router();
const User = require('./models/User');
router.get('/test101', async (req, res) => {
    const search = req.query.search;
    const users = await User.find({ $where: 'this.name == "' + search + '"' });
    res.json(users);
});
module.exports = router;
