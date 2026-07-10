// Vulnerable: Command injection via environment variable in exec
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.post('/test059', (req, res) => {
    const repo = req.body.repo;
    exec('git clone ' + repo + ' /tmp/checkout', (err, stdout) => {
        res.json({ output: stdout });
    });
});
module.exports = router;
