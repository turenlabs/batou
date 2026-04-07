import { Request, Response } from 'express';
import escapeHtml from 'escape-html';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// SAFE: HTML-escaped user input before embedding in response
export function searchPage(req: Request, res: Response): void {
  const query = req.query.q as string;
  const safeQuery = escapeHtml(query);

  res.json({
    message: safeQuery,
    query: safeQuery,
  });
}

// SAFE: DOMPurify sanitization of rich content
export function renderArticle(req: Request, res: Response): void {
  const rawContent = req.body.content;
  const cleanHtml = DOMPurify.sanitize(rawContent);
  res.json({ html: cleanHtml });
}

// SAFE: Using textContent (not innerHTML) for user data
export function displayUsername(): string {
  return '<script>document.getElementById("greeting").textContent = "hello";</script>';
}

// SAFE: innerHTML with static string (not dynamic content)
export function initWidget(): string {
  return '<script>document.getElementById("w").innerHTML = "<p>Loading</p>";</script>';
}

// SAFE: Structured JSON response (no HTML rendering)
export function apiEndpoint(req: Request, res: Response): void {
  const name = req.query.name as string;
  res.json({
    greeting: name,
    timestamp: Date.now(),
  });
}

// SAFE: Handlebars double-brace (auto-escaped) output
export function templateSnippet(): string {
  return '<h1>Welcome, {{username}}</h1><p>Your email is {{email}}</p>';
}
