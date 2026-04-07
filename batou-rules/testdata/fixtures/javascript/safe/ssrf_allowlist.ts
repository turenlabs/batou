import { Request, Response } from 'express';
import axios from 'axios';
import { URL } from 'url';
import dns from 'dns';
import net from 'net';

// Allowlist of permitted external domains
const ALLOWED_DOMAINS = new Set([
  'api.github.com',
  'api.stripe.com',
  'hooks.slack.com',
]);

// SAFE: URL validation with allowlist before making request
export async function proxyRequest(req: Request, res: Response): Promise<void> {
  const targetUrl = req.query.url as string;

  // SAFE: Parse and validate URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    res.status(400).json({ error: 'Invalid URL' });
    return;
  }

  // SAFE: Only allow HTTPS
  if (parsedUrl.protocol !== 'https:') {
    res.status(400).json({ error: 'Only HTTPS URLs are allowed' });
    return;
  }

  // SAFE: Check against domain allowlist
  if (!ALLOWED_DOMAINS.has(parsedUrl.hostname)) {
    res.status(403).json({ error: 'Domain not in allowlist' });
    return;
  }

  // SAFE: Resolve hostname and verify it's not a private IP
  const addresses = await dns.promises.resolve4(parsedUrl.hostname);
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      res.status(403).json({ error: 'Cannot access internal addresses' });
      return;
    }
  }

  const response = await axios.get(targetUrl, {
    maxRedirects: 0, // SAFE: Disable redirects
    timeout: 5000,
  });

  res.json({ data: response.data });
}

function isPrivateIP(ip: string): boolean {
  return net.isIP(ip) !== 0 && (
    ip.startsWith('10.') ||
    ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip === '0.0.0.0' ||
    ip === '169.254.169.254'
  );
}
