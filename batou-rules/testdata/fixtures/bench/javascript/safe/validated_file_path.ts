import { Request, Response } from 'express';
import path from 'path';
import fs from 'fs';

const UPLOAD_DIR = '/var/www/uploads';
const STATIC_DIR = '/var/www/static';

// SAFE: Path validated with resolve + startsWith check
export function downloadFile(req: Request, res: Response): void {
  const fileName = req.params.name;
  const resolvedPath = path.resolve(UPLOAD_DIR, fileName);

  if (!resolvedPath.startsWith(UPLOAD_DIR)) {
    res.status(403).json({ error: 'Access denied' });
    return;
  }

  res.sendFile(resolvedPath);
}

// SAFE: Using allowlist of file names
export function getStaticAsset(req: Request, res: Response): void {
  const allowedFiles = ['logo.png', 'favicon.ico', 'robots.txt', 'manifest.json'];
  const requested = req.params.file;

  if (!allowedFiles.includes(requested)) {
    res.status(404).json({ error: 'Not found' });
    return;
  }

  const safePath = path.join(STATIC_DIR, requested);
  res.sendFile(safePath);
}

// SAFE: basename strips directory traversal components
export function serveDocument(req: Request, res: Response): void {
  const rawName = req.query.doc as string;
  const safeName = path.basename(rawName);
  const fullPath = path.join(UPLOAD_DIR, safeName);

  if (!fs.existsSync(fullPath)) {
    res.status(404).json({ error: 'Document not found' });
    return;
  }

  res.sendFile(fullPath);
}

// SAFE: res.render with string literal template name
export function profilePage(req: Request, res: Response): void {
  const userId = req.params.id;
  res.render('profile', { userId, title: 'User Profile' });
}
