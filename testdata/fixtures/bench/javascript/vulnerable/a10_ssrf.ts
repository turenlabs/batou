// Source: OWASP Juice Shop - SSRF via profile image URL
// Expected: GTSS-SSRF-001 (URL from User Input)
// OWASP: A10:2021 - Server-Side Request Forgery

import { Request, Response } from 'express';
import http from 'http';
import https from 'https';

export function fetchProfileImage(req: Request, res: Response): void {
  const imageUrl = req.body.imageUrl;
  const client = imageUrl.startsWith('https') ? https : http;
  client.get(imageUrl, (proxyRes) => {
    res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'image/png');
    proxyRes.pipe(res);
  }).on('error', (err) => {
    res.status(500).json({ error: 'Failed to fetch image' });
  });
}

export function webhookProxy(req: Request, res: Response): void {
  const targetUrl = req.query.url as string;
  const options = new URL(targetUrl);
  http.get(options, (proxyRes) => {
    let data = '';
    proxyRes.on('data', (chunk) => data += chunk);
    proxyRes.on('end', () => res.json({ response: data }));
  });
}
