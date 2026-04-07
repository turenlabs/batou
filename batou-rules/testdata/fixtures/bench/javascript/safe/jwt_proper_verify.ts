import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

const ALLOWED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com',
];

// SAFE: crypto.randomBytes for token generation (not Math.random)
export function generateSessionToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

// SAFE: crypto.scrypt for password hashing (not MD5/SHA1)
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derived) => {
      if (err) reject(err);
      resolve(salt + ':' + derived.toString('hex'));
    });
  });
}

// SAFE: timingSafeEqual for password comparison (not ==)
export async function verifyPassword(stored: string, candidate: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  return new Promise((resolve, reject) => {
    crypto.scrypt(candidate, salt, 64, (err, derived) => {
      if (err) reject(err);
      const storedBuf = Buffer.from(hash, 'hex');
      resolve(crypto.timingSafeEqual(storedBuf, derived));
    });
  });
}

// SAFE: Explicit CORS origin allowlist (not wildcard *)
export function corsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin as string;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
}

// SAFE: Secure cookie settings (httpOnly, secure, sameSite)
export function setSessionCookie(res: Response, token: string): void {
  res.cookie('session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000,
    path: '/',
  });
}

// SAFE: Strong password policy (12+ chars, mixed requirements)
export function validatePasswordStrength(password: string): boolean {
  if (password.length < 12) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return true;
}
