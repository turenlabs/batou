import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';

const ALLOWED_DIR = path.resolve(__dirname, 'public', 'files');

// SAFE: Path traversal prevention with resolve + startsWith check
export function servePublicFile(req: Request, res: Response): void {
  const fileName = req.params.file;

  // SAFE: Resolve the full path and verify it stays within the allowed directory
  const resolvedPath = path.resolve(ALLOWED_DIR, fileName);

  if (!resolvedPath.startsWith(ALLOWED_DIR)) {
    res.status(403).json({ error: 'Access denied' });
    return;
  }

  // Check file exists
  if (!fs.existsSync(resolvedPath)) {
    res.status(404).json({ error: 'File not found' });
    return;
  }

  res.sendFile(resolvedPath);
}

// SAFE: Using sendFile with root option and sanitized filename
export function downloadDocument(req: Request, res: Response): void {
  const fileName = req.params.filename;

  // SAFE: Strip path separators and null bytes from filename
  const sanitizedName = path.basename(fileName).replace(/\0/g, '');

  // Validate against allowlist of extensions
  const allowedExtensions = ['.pdf', '.txt', '.csv'];
  const ext = path.extname(sanitizedName).toLowerCase();

  if (!allowedExtensions.includes(ext)) {
    res.status(400).json({ error: 'File type not allowed' });
    return;
  }

  // SAFE: Use root option to restrict to specific directory
  res.sendFile(sanitizedName, { root: path.resolve(__dirname, 'documents') });
}
