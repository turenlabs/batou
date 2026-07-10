// Vulnerable: XSS via template literal in res.send
const express = require('express');
const router = express.Router();
router.get('/test023', (req, res) => {
    const comment = req.body.comment;
    res.send(`<div class="comment">${comment}</div>`);
});
module.exports = router;
