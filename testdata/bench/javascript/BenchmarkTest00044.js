// Safe: Command injection prevented via spawn with argument array
const express = require('express');
const { spawn } = require('child_process');
const router = express.Router();
router.post('/test044', (req, res) => {
    const host = req.body.host;
    const proc = spawn('ping', ['-c', '4', host]);
    let output = '';
    proc.stdout.on('data', (data) => { output += data; });
    proc.on('close', () => { res.send(output); });
});
module.exports = router;
