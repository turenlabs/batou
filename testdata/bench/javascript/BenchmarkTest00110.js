// Safe: NoSQL injection prevented via type coercion
const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const User = require('./models/User');
router.post('/test110', async (req, res) => {
    const username = String(req.body.username);
    const password = String(req.body.password);
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    res.json({ token: 'abc123' });
});
module.exports = router;
