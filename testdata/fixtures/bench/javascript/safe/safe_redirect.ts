import { Request, Response } from 'express';
import { URL } from 'url';

const ALLOWED_REDIRECT_HOSTS = new Set([
  'app.example.com',
  'docs.example.com',
  'www.example.com',
]);

// SAFE: Allowlist-based redirect validation
export function safeRedirect(req: Request, res: Response): void {
  const target = req.query.next as string;

  try {
    const parsed = new URL(target, 'https://app.example.com');
    if (!ALLOWED_REDIRECT_HOSTS.has(parsed.hostname)) {
      res.redirect('/');
      return;
    }
    if (parsed.protocol !== 'https:') {
      res.redirect('/');
      return;
    }
    res.redirect(parsed.href);
  } catch {
    res.redirect('/');
  }
}

// SAFE: Relative-path-only redirect (no external URLs)
export function loginRedirect(req: Request, res: Response): void {
  const returnPath = req.query.returnTo as string;

  if (!returnPath || !returnPath.startsWith('/') || returnPath.startsWith('//')) {
    res.redirect('/dashboard');
    return;
  }

  res.redirect(returnPath);
}

// SAFE: Hardcoded redirect target
export function logoutHandler(req: Request, res: Response): void {
  req.session?.destroy(() => {
    res.redirect('/login');
  });
}
