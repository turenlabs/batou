import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

// VULNERABLE: JWT verification with 'none' algorithm allowed
export function verifyToken(req: Request, res: Response): void {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  // VULNERABLE: jwt.verify with algorithms including 'none'
  // An attacker can forge tokens by setting alg: "none" and removing the signature
  const decoded = jwt.verify(token, JWT_SECRET, {
    algorithms: ['HS256', 'none'],
  });

  res.json({ user: decoded });
}

// VULNERABLE: Using jwt.decode without verification
export function getUserFromToken(req: Request, res: Response): void {
  const token = req.cookies.session;

  // VULNERABLE: jwt.decode does NOT verify the signature
  const payload = jwt.decode(token);

  if (!payload) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  res.json({ userId: (payload as any).sub, role: (payload as any).role });
}
