// Safe: Redirect prevented via URL map lookup
const express = require('express');
const router = express.Router();
const SHORTCUTS = {
    'docs': 'https://docs.example.com',
    'blog': 'https://blog.example.com',
    'support': 'https://support.example.com'
};
router.get('/goto/:key', (req, res) => {
    const key = req.params.key;
    const url = SHORTCUTS[key];
    if (!url) return res.status(404).send('Unknown shortcut');
    res.redirect(url);
});
module.exports = router;
