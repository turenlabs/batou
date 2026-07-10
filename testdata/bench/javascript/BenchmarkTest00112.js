// Safe: NoSQL injection prevented via explicit field update
const express = require('express');
const router = express.Router();
const User = require('./models/User');
router.put('/test112', async (req, res) => {
    const userId = String(req.body.userId);
    const newEmail = String(req.body.email);
    await User.updateOne({ _id: userId }, { $set: { email: newEmail } });
    res.json({ status: 'updated' });
});
module.exports = router;
