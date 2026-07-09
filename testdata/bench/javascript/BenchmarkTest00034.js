// Safe: XSS prevented by sending JSON response
const express = require('express');
const router = express.Router();
router.get('/test034', (req, res) => {
    const data = req.query.data;
    res.json({ result: data });
});
module.exports = router;
