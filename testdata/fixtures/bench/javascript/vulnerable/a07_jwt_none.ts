// Source: OWASP Juice Shop - JWT "none" algorithm attack
// Expected: BATOU-AUTH-001 (Hardcoded Credentials), BATOU-SEC-005, BATOU-JWT-002 (JWT none algorithm)
// OWASP: A07:2021 - Identification and Authentication Failures

import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

const JWT_SECRET = 'super-secret-key-change-me';

export function createToken(userId: number, role: string): string {
  return jwt.sign({ userId, role }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '24h',
  });
}

export function verifyToken(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
    (req as any).user = decoded;
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}
