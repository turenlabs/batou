// Safe: Command injection prevented via allowlist validation
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
const ALLOWED_COMMANDS = ['status', 'version', 'info'];
router.get('/test046', (req, res) => {
    const cmd = req.query.cmd;
    if (!ALLOWED_COMMANDS.includes(cmd)) {
        return res.status(400).json({ error: 'Command not allowed' });
    }
    exec('systemctl ' + cmd, (err, stdout) => { res.send(stdout); });
});
module.exports = router;
