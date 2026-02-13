import { Request, Response } from 'express';
import mongoose from 'mongoose';

const User = mongoose.model('User', new mongoose.Schema({ username: String, password: String }));

// VULNERABLE: req.body passed directly to findOne (operator injection)
export async function login(req: Request, res: Response): Promise<void> {
  const user = await User.findOne(req.body);
  if (!user) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }
  res.json({ status: 'authenticated' });
}

// VULNERABLE: JSON.parse of user input in query
export async function search(req: Request, res: Response): Promise<void> {
  const results = await User.find(JSON.parse(req.body.filter));
  res.json({ results });
}

// VULNERABLE: req.body.id passed to updateMany (Juice Shop updateProductReviews pattern)
export async function updateReviews(req: Request, res: Response): Promise<void> {
  await mongoose.connection.db.collection('reviews').updateMany(
    { _id: req.body.id },
    { $set: { message: req.body.message } }
  );
  res.json({ status: 'updated' });
}
