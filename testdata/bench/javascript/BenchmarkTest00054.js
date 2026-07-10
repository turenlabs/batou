// Safe: Command injection prevented via fs.appendFile instead of shell
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.get('/test054', (req, res) => {
    const userAgent = req.headers['user-agent'];
    fs.appendFile('/var/log/visitors.log', userAgent + '\n', (err) => {
        res.send('Logged');
    });
});
module.exports = router;
