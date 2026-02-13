import { Request, Response } from 'express';

// Juice Shop redirect.ts style: bypassable URL allowlist using .includes()
// url.includes("allowed.com") can be bypassed with "allowed.com.evil.com"

const allowedRedirectTargets = ['github.com', 'blockchain.info'];

export function handleRedirect(req: Request, res: Response): void {
  const toUrl = req.query.to as string;

  // VULNERABLE: url.includes() is not a secure way to validate URLs
  // Bypass: /redirect?to=https://github.com.evil.com/phishing
  // Bypass: /redirect?to=https://evil.com/github.com
  let allowed = false;
  for (const target of allowedRedirectTargets) {
    if (toUrl.includes(target)) {
      allowed = true;
      break;
    }
  }

  if (allowed) {
    res.redirect(toUrl);
  } else {
    res.redirect('/');
  }
}

export function handleReturnUrl(req: Request, res: Response): void {
  const returnUrl = req.query.returnUrl as string;

  // VULNERABLE: startsWith("http") allows any HTTP URL
  if (returnUrl.startsWith("http")) {
    res.redirect(returnUrl);
  }
}
