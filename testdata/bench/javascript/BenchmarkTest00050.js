// Safe: Command injection prevented via regex validation
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.post('/test050', (req, res) => {
    const pkg = req.body.package;
    if (!/^[a-zA-Z0-9@/_-]+$/.test(pkg)) {
        return res.status(400).json({ error: 'Invalid package name' });
    }
    exec('npm info ' + pkg, (err, stdout) => { res.json({ info: stdout }); });
});
module.exports = router;
