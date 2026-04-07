import { Request, Response } from 'express';
import axios from 'axios';
import fetch from 'node-fetch';

// VULNERABLE: SSRF via user-controlled URL passed to axios
export async function proxyRequest(req: Request, res: Response): Promise<void> {
  const targetUrl = req.query.url as string;

  // VULNERABLE: axios.get with user-controlled URL (SSRF)
  const response = await axios.get(targetUrl);
  res.json({ data: response.data });
}

// VULNERABLE: SSRF via fetch with user-controlled URL
export async function fetchWebhook(req: Request, res: Response): Promise<void> {
  const webhookUrl = req.body.callback_url;

  // VULNERABLE: fetch with user-controlled URL
  const response = await fetch(webhookUrl, {
    method: 'POST',
    body: JSON.stringify({ status: 'complete' }),
    headers: { 'Content-Type': 'application/json' },
  });

  res.json({ status: response.status });
}

// VULNERABLE: SSRF with redirect following enabled
export async function fetchPage(req: Request, res: Response): Promise<void> {
  const pageUrl = req.query.url as string;

  const response = await axios.get(pageUrl, {
    maxRedirects: 10,
    followRedirects: true,
  });

  res.send(response.data);
}
