// Vulnerable: Command injection via variable indirection
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.get('/test047', (req, res) => {
    const input = req.query.tool;
    const command = input;
    const fullCmd = 'npm ' + command;
    exec(fullCmd, (err, stdout) => { res.send(stdout); });
});
module.exports = router;
