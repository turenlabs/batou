// Vulnerable: SSRF via fetch in POST handler
const express = require('express');
const router = express.Router();
router.post('/test087', async (req, res) => {
    const webhookUrl = req.body.webhook;
    const payload = JSON.stringify({ status: 'completed' });
    const response = await fetch(webhookUrl, {
        method: 'POST',
        body: payload,
        headers: { 'Content-Type': 'application/json' }
    });
    res.json({ sent: response.ok });
});
module.exports = router;
