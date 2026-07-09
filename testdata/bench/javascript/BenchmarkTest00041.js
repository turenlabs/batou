// Vulnerable: Command injection via exec with user input
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.get('/test041', (req, res) => {
    const filename = req.query.file;
    exec('cat /var/log/' + filename, (err, stdout) => {
        res.send(stdout);
    });
});
module.exports = router;
