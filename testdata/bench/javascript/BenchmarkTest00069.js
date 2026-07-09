// Vulnerable: Path traversal via res.download
const express = require('express');
const router = express.Router();
router.get('/test069', (req, res) => {
    const file = req.query.file;
    res.download('/exports/' + file);
});
module.exports = router;
