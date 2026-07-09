// Vulnerable: NoSQL injection via replaceOne with user data
const express = require('express');
const router = express.Router();
const Config = require('./models/Config');
router.put('/test119', async (req, res) => {
    const id = req.params.id;
    const replacement = req.body;
    await Config.replaceOne({ _id: id }, replacement);
    res.json({ status: 'replaced' });
});
module.exports = router;
