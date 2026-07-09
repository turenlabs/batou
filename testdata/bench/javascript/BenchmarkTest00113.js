// Vulnerable: NoSQL injection via deleteMany with user filter
const express = require('express');
const router = express.Router();
const Log = require('./models/Log');
router.delete('/test113', async (req, res) => {
    const filter = req.body;
    await Log.deleteMany(filter);
    res.json({ status: 'deleted' });
});
module.exports = router;
