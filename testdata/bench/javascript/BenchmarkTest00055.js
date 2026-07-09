// Vulnerable: Command injection via spawn with shell option
const express = require('express');
const { spawn } = require('child_process');
const router = express.Router();
router.get('/test055', (req, res) => {
    const query = req.query.q;
    const proc = spawn('grep ' + query + ' /var/data/records.txt', { shell: true });
    let output = '';
    proc.stdout.on('data', (data) => { output += data; });
    proc.on('close', () => { res.send(output); });
});
module.exports = router;
