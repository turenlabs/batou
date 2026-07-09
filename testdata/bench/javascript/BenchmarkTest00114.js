// Safe: NoSQL injection prevented via date-only filter
const express = require('express');
const router = express.Router();
const Log = require('./models/Log');
router.delete('/test114', async (req, res) => {
    const beforeDate = new Date(req.body.before);
    if (isNaN(beforeDate.getTime())) {
        return res.status(400).json({ error: 'Invalid date' });
    }
    await Log.deleteMany({ createdAt: { $lt: beforeDate } });
    res.json({ status: 'deleted' });
});
module.exports = router;
