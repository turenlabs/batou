// Safe: SSRF prevented via enum mapping
const express = require('express');
const router = express.Router();
const SERVICE_MAP = {
    'users': 'https://internal-users.svc:8080',
    'orders': 'https://internal-orders.svc:8080',
    'products': 'https://internal-products.svc:8080'
};
router.get('/test094', async (req, res) => {
    const service = req.query.service;
    const baseUrl = SERVICE_MAP[service];
    if (!baseUrl) return res.status(400).json({ error: 'Unknown service' });
    const response = await fetch(baseUrl + '/health');
    res.json(await response.json());
});
module.exports = router;
