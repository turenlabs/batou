// Vulnerable: Command injection via header in exec
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.get('/test053', (req, res) => {
    const userAgent = req.headers['user-agent'];
    exec('echo "' + userAgent + '" >> /var/log/visitors.log', (err) => {
        res.send('Logged');
    });
});
module.exports = router;
