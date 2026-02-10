import { Request, Response } from 'express';

// Juice Shop style: open redirect with user-controlled URL
export function handleRedirect(req: Request, res: Response): void {
  const redirectTo = req.query.to as string;

  // VULNERABLE: user-controlled redirect target, no URL validation
  // Attacker can use: /redirect?to=https://evil.com
  res.redirect(redirectTo);
}

export function handleLogin(req: Request, res: Response): void {
  const { username, password } = req.body;
  const returnUrl = req.query.returnUrl as string;

  // Simulate authentication
  if (username === 'admin') {
    // VULNERABLE: open redirect after login
    // location.href assignment with user-controlled url
    res.send(`<script>window.location.href = '${returnUrl}';</script>`);
  } else {
    res.status(401).send('Unauthorized');
  }
}
