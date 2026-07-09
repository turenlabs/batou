// Vulnerable: XSS via res.send with unsanitized user input
const express = require('express');
const router = express.Router();
router.get('/test021', (req, res) => {
    const name = req.query.name;
    res.send('<h1>Hello ' + name + '</h1>');
});
module.exports = router;
