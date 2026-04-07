import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';

// SAFE: Load RSA key pair from files (not hardcoded)
const privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf-8');
const publicKey = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf-8');

// SAFE: JWT signing with RS256 (asymmetric) algorithm
export function signToken(userId: string, role: string): string {
  return jwt.sign(
    { sub: userId, role, iss: 'myapp' },
    privateKey,
    {
      algorithm: 'RS256',
      expiresIn: '1h',
      audience: 'myapp-api',
    }
  );
}

// SAFE: JWT verification with explicit algorithm and proper key
export function verifyToken(req: Request, res: Response): void {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  try {
    // SAFE: Explicit algorithms list (no 'none'), public key verification
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      audience: 'myapp-api',
      issuer: 'myapp',
    });

    res.json({ user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
