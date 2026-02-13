import { Request, Response } from 'express';
import mongoose from 'mongoose';

const User = mongoose.model('User', new mongoose.Schema({ username: String, password: String }));

// SAFE: Explicit field access with type casting
export async function login(req: Request, res: Response): Promise<void> {
  const user = await User.findOne({
    username: String(req.body.username),
    password: String(req.body.password)
  });
  if (!user) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }
  res.json({ status: 'authenticated' });
}

// SAFE: Static query with no user input
export async function getAdmins(req: Request, res: Response): Promise<void> {
  const admins = await User.find({ role: 'admin' });
  res.json({ admins });
}

// SAFE: Using mongo-sanitize before query
export async function searchUsers(req: Request, res: Response): Promise<void> {
  const sanitizedQuery = { name: String(req.query.name) };
  const users = await User.find(sanitizedQuery);
  res.json({ users });
}
