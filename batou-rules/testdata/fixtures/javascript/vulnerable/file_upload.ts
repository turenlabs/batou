import { Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';

// VULNERABLE: File upload with no restrictions (no size limit, no type filtering)
const upload = multer({
  dest: 'uploads/',
});

// VULNERABLE: multer with no file size limit
export const uploadMiddleware = upload.single('avatar');

export function handleUpload(req: Request, res: Response): void {
  if (!req.file) {
    res.status(400).json({ error: 'No file uploaded' });
    return;
  }

  // VULNERABLE: using original filename without sanitization
  const originalName = req.file.originalname;
  const destPath = path.join('uploads', originalName);

  // VULNERABLE: fs operation with unsanitized filename
  fs.renameSync(req.file.path, destPath);

  res.json({
    status: 'uploaded',
    filename: originalName,
    path: destPath,
  });
}

// VULNERABLE: no file type validation
export function handleDocumentUpload(req: Request, res: Response): void {
  const fileContent = req.body.content;
  const fileName = req.body.name;

  // VULNERABLE: writing arbitrary content with user-controlled filename
  fs.writeFileSync(path.join('documents', fileName), fileContent);
  res.json({ status: 'saved' });
}
