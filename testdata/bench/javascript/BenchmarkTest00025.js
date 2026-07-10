// Vulnerable: XSS via innerHTML assignment
const express = require('express');
const router = express.Router();
router.get('/test025', (req, res) => {
    const userInput = req.query.content;
    const html = '<script>document.getElementById("output").innerHTML = "' + userInput + '";</script>';
    res.send(html);
});
module.exports = router;
