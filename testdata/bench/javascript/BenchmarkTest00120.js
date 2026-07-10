// Safe: NoSQL injection prevented via Zod schema validation
const express = require('express');
const { z } = require('zod');
const router = express.Router();
const Config = require('./models/Config');
const configSchema = z.object({
    key: z.string().max(100),
    value: z.string().max(1000),
    enabled: z.boolean()
});
router.put('/test120', async (req, res) => {
    const parsed = configSchema.parse(req.body);
    await Config.replaceOne({ _id: req.params.id }, parsed);
    res.json({ status: 'replaced' });
});
module.exports = router;
