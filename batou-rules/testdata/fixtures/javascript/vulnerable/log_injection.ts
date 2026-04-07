import { Request, Response } from 'express';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  transports: [new winston.transports.Console()],
});

// VULNERABLE: User input logged directly without sanitization
export function loginAttempt(req: Request, res: Response): void {
  const { username } = req.body;

  // VULNERABLE: console.log with unsanitized request data (log injection)
  // Attacker can inject: "admin\n[INFO] Login successful for admin"
  console.log('Login attempt for user: ' + req.body.username);

  // VULNERABLE: winston logger with unsanitized request data
  logger.info(`Failed login attempt for user: ${username} from IP: ${req.headers['x-forwarded-for']}`);

  res.status(401).json({ error: 'Invalid credentials' });
}

// VULNERABLE: Logging sensitive data (password)
export function debugLogin(req: Request, res: Response): void {
  const { username, password } = req.body;

  // VULNERABLE: Sensitive data in logs - logging password
  console.log('Debug auth - username: ' + username + ', password: ' + password);
  logger.debug(`Authentication attempt with credentials - password: ${password}`);

  res.json({ status: 'ok' });
}
