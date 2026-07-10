// Vulnerable: NoSQL injection via updateOne with tainted data
const express = require('express');
const router = express.Router();
const User = require('./models/User');
router.put('/test111', async (req, res) => {
    const filter = req.body.filter;
    const update = req.body.update;
    await User.updateOne(filter, update);
    res.json({ status: 'updated' });
});
module.exports = router;
