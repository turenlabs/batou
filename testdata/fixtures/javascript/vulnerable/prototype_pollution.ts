import { Request, Response } from 'express';
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({ name: String, email: String, role: String });
const User = mongoose.model('User', UserSchema);

// VULNERABLE: Prototype pollution via spread of req.body
export async function updateProfile(req: Request, res: Response): Promise<void> {
  const userId = req.params.id;

  // VULNERABLE: { ...req.body } allows attacker to inject any property
  // An attacker can send: { "name": "hacker", "__proto__": { "isAdmin": true } }
  const updateData = { ...req.body };

  await User.findByIdAndUpdate(userId, updateData);
  res.json({ status: 'updated' });
}

// VULNERABLE: Object.assign with req.body
export async function createUser(req: Request, res: Response): Promise<void> {
  const defaults = { role: 'user', active: true };

  // VULNERABLE: Object.assign({}, req.body) allows attacker to override role
  const userData = Object.assign({}, req.body);
  Object.assign(userData, defaults);

  const user = await User.create(userData);
  res.status(201).json(user);
}

// VULNERABLE: render options injection via req.body spread
export function renderDashboard(req: Request, res: Response): void {
  // VULNERABLE: res.render with spread of req.body into options
  // Attacker can inject { "layout": "../../../etc/passwd" }
  res.render('dashboard', { ...req.body });
}
