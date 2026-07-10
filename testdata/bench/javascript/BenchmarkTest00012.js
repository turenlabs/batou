// Safe: SQL injection prevented via Prisma tagged template
const express = require('express');
const { PrismaClient, Prisma } = require('@prisma/client');
const prisma = new PrismaClient();
const router = express.Router();
router.get('/test012', async (req, res) => {
    const email = req.query.email;
    const users = await prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE email = ${email}`);
    res.json(users);
});
module.exports = router;
