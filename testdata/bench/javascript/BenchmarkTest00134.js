// Safe: Scheduled action via setTimeout with function reference
const express = require('express');
const router = express.Router();
const ACTIONS = {
    'cleanup': () => console.log('Cleaning up'),
    'notify': () => console.log('Sending notification')
};
router.post('/test134', (req, res) => {
    const actionName = req.body.action;
    const fn = ACTIONS[actionName];
    if (!fn) return res.status(400).json({ error: 'Unknown action' });
    setTimeout(fn, 1000);
    res.json({ status: 'scheduled' });
});
module.exports = router;
