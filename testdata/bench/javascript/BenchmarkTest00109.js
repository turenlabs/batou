// Vulnerable: NoSQL injection via findOne with unsanitized query
const express = require('express');
const router = express.Router();
const User = require('./models/User');
router.post('/test109', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const user = await User.findOne({ username: username, password: password });
    if (user) res.json({ token: 'abc123' });
    else res.status(401).json({ error: 'Invalid credentials' });
});
module.exports = router;
