import crypto from 'crypto';

// VULNERABLE: MD5 for password hashing
export function hashPassword(password: string): string {
  // VULNERABLE: crypto.createHash('md5') - weak hash for passwords
  return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABLE: SHA-1 for token generation
export function generateVerificationToken(userId: string): string {
  // VULNERABLE: crypto.createHash('sha1') - weak hash algorithm
  return crypto.createHash('sha1').update(userId + Date.now()).digest('hex');
}

// VULNERABLE: Math.random for session token generation
export function generateSessionToken(): string {
  // VULNERABLE: Math.random() is not cryptographically secure
  const token = Math.random().toString(36).substring(2) +
    Math.random().toString(36).substring(2);
  return token;
}

// VULNERABLE: Disabled TLS certificate verification
export function createInsecureClient(): void {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// VULNERABLE: Hardcoded IV for encryption
export function encryptData(data: string, key: Buffer): string {
  const iv = 'abcdef1234567890';
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
