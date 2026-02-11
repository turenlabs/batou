// Source: OWASP Juice Shop - File download with path traversal
// Expected: GTSS-TRV-007 (Express sendFile with variable path)
// OWASP: A01:2021 - Broken Access Control (Path Traversal)

import { Request, Response } from 'express';
import path from 'path';

const UPLOAD_DIR = './uploads';

export function downloadFile(req: Request, res: Response): void {
  const fileName = req.params.file;
  const filePath = path.join(UPLOAD_DIR, fileName);
  res.sendFile(filePath);
}

export function serveDocument(req: Request, res: Response): void {
  const docName = req.query.name as string;
  const docPath = path.join('./documents', docName);
  res.download(docPath);
}
