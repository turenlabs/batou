import crypto from 'crypto';
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;

// SAFE: bcrypt for password hashing
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

// SAFE: bcrypt for password verification
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// SAFE: crypto.randomBytes for secure token generation
export function generateSessionToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

// SAFE: SHA-256 for integrity checks (not passwords)
export function checksumFile(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// SAFE: AES-256-GCM for authenticated encryption with random IV
export function encryptData(data: string, key: Buffer): { encrypted: string; iv: string; tag: string } {
  const iv = crypto.randomBytes(16); // SAFE: random IV per encryption
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return { encrypted, iv: iv.toString('hex'), tag };
}

// SAFE: Secure random for CSRF tokens
export function generateCSRFToken(): string {
  return crypto.randomBytes(24).toString('base64url');
}
