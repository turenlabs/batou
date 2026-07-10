// Safe: Command injection prevented via parseInt for numeric arg
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.get('/test048', (req, res) => {
    const count = parseInt(req.query.count, 10);
    if (isNaN(count) || count < 1 || count > 100) {
        return res.status(400).json({ error: 'Invalid count' });
    }
    exec('head -n ' + count + ' /var/log/app.log', (err, stdout) => { res.send(stdout); });
});
module.exports = router;
