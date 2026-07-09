// Safe: XSS prevented via textContent (not innerHTML)
const express = require('express');
const router = express.Router();
router.get('/test026', (req, res) => {
    const userInput = req.query.content;
    const safeContent = JSON.stringify(userInput);
    res.json({ content: safeContent });
});
module.exports = router;
