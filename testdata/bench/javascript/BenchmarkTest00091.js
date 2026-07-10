// Vulnerable: SSRF via axios.post with user URL
const express = require('express');
const axios = require('axios');
const router = express.Router();
router.post('/test091', async (req, res) => {
    const callbackUrl = req.body.callback;
    const data = { event: 'order_complete', orderId: 123 };
    await axios.post(callbackUrl, data);
    res.json({ status: 'callback sent' });
});
module.exports = router;
