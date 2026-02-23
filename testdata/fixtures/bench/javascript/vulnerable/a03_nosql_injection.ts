// Source: OWASP NodeGoat - NoSQL injection in user search
// Expected: BATOU-INJ-007 (NoSQL Injection)
// OWASP: A03:2021 - Injection (NoSQL Injection)

import { Request, Response } from 'express';
import { MongoClient } from 'mongodb';

const client = new MongoClient('mongodb://localhost:27017');

export async function searchUsers(req: Request, res: Response): Promise<void> {
  const db = client.db('app');
  const username = req.body.username;
  const password = req.body.password;
  const user = await db.collection('users').findOne({
    username: username,
    password: password,
  });
  if (user) {
    res.json({ status: 'authenticated', user: user.username });
  } else {
    res.status(401).json({ error: 'Authentication failed' });
  }
}
