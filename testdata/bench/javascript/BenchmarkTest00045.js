// Vulnerable: Command injection via execSync
const express = require('express');
const { execSync } = require('child_process');
const router = express.Router();
router.get('/test045', (req, res) => {
    const dir = req.query.dir;
    const result = execSync('ls -la ' + dir);
    res.send('<pre>' + result.toString() + '</pre>');
});
module.exports = router;
