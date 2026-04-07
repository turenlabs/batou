import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';

// Juice Shop style: serve files with path traversal vulnerability
export function servePublicFile(req: Request, res: Response): void {
  const fileName = req.params.file;

  // VULNERABLE: res.sendFile with user input and no path validation
  res.sendFile(fileName, { root: './public/files' });
}

// VULNERABLE: fs.readFile with user-controlled path
export function readDocument(req: Request, res: Response): void {
  const filePath = req.query.path as string;

  // VULNERABLE: fs.readFileSync with unsanitized user input
  fs.readFileSync(filePath, 'utf-8');
}

// VULNERABLE: res.download with user-controlled variable path
export function downloadFile(req: Request, res: Response): void {
  const requestedFile = req.params.filename;

  // VULNERABLE: path.join without traversal check
  const fullPath = path.join(__dirname, 'uploads', requestedFile);
  res.download(fullPath);
}

// VULNERABLE: fs operation with direct user input from req.query
export function viewLog(req: Request, res: Response): void {
  const logFile = req.query.file as string;
  fs.readFile(logFile, 'utf-8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.type('text/plain').send(data);
  });
}
