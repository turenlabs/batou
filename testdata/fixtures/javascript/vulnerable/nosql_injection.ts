import { Request, Response } from 'express';
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({ username: String, password: String, role: String });
const User = mongoose.model('User', UserSchema);

// VULNERABLE: NoSQL injection via JSON.parse of user input in MongoDB query
export async function login(req: Request, res: Response): Promise<void> {
  const { username, password } = req.body;

  // An attacker can send: { "username": {"$gt": ""}, "password": {"$gt": ""} }
  const user = await User.findOne(JSON.parse(req.body.filter));
  if (!user) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  res.json({ status: 'authenticated', user: user.username });
}

// VULNERABLE: NoSQL injection via $where operator with user input
export async function searchUsers(req: Request, res: Response): Promise<void> {
  const searchTerm = req.query.search as string;

  const users = await User.find({
    "$where": "this.username.includes('" + searchTerm + "')"
  });

  res.json({ users });
}
